# MISPHunter

## What is it?

MISPHunter allows you to use a MISP instance to track newly-built infrastructure using custom 3rd party searches.

In short, you can easily load up a MISP event with your complex Censys or Shodan searches and sit back while 
MISPHunter automatically populates the event with all the relevant datapoints it finds. It then uses those datapoints 
to attempt to discover additional related infrastructure.

## What isn't it?

Anything other than an ongoing pet-project of mine. Pull requests are always welcome. Don't expect support - I'll try to make it better 
when I can, but frankly I'm shocked I made it this far.

## How to use it

### Initial setup

First, make sure that your configurations are properly set in the `misphunter.conf` file. Slugs should remain untouched.

Next, add the custom objects and custom taxonomies included under `custom_objects/objects` and 
`custom_taxonomies/taxonomies` into your MISP instance.

Generally this can be accomplished by running the following as `root`, assuming the `www-data` account 
operates your MISP instance:

```
cp -R ./custom_objects/objects/* /var/www/MISP/app/files/misp-objects/objects
chown -R www-data:www-data /var/www/MISP/app/files/misp-objects/objects/misphunter-*
cp -R ./custom_taxonomies/taxonomies/* /var/www/MISP/app/files/taxonomies
chown -R www-data:www-data /var/www/MISP/app/files/taxonomies/misphunter
```

Browse to `https://<your_misp_url>/objectTemplates/index` and click `Update Objects` to ensure the objects are up to date. 
Check to make sure that the `misphunter-*` object templates are all loaded and active.

Browse to `https://<your_misp_url>/taxonomies/index` and click `Update Taxonomies` to ensure the taxonomies are up to date. 
Make sure the MISPHunter Taxonomy is enabled. You may have to click the 'play' icon to enable them. 
When viewing the taxonomy (eyeball button) you should see it populated with a gradient of colored tags on the right-hand side. 
If those tags do not appear, click the checkbox to select all tags, then click the + sign to `Create / update selected tags`.

Make sure you've got the right dependencies. `pip install -r REQUIREMENTS` (latest version was created with 3.9.7)

That's it! The initial setup is complete.

### Building a MISP Event

In order to start tracking a Censys or Shodan search, you must first create a new MISP Event that will house the searches related to the 
infrastructure you are hunting. Once the new event has been created, click `Add Object -> threat-hunting -> misphunter-seed`.

Specify the service you wish to search (e.g. `shodan`, `censys-v1`, `censys-v2`), input the raw search string you wish to run, and make 
sure `Enabled` is set to `1`. You can specify an `Update-freq` if you like, or change it at a later time, but it defaults to `24` hours.

Save your misphunter-seed object and create any additional ones that might find related infrastructure if you wish.

![image](https://user-images.githubusercontent.com/6147794/132043882-29fa1293-e201-4a1a-bec6-760a422a9d3c.png)

### LAUNCH!

`python misphunter.py` - you can use the `-h` flag to see available options, but most of them are debugging-related at the moment.

Once MISPHunter runs, it will find all enabled seeds in your MISP instance. If their `last-run` timestamp is > their `update-freq` 
value, they'll be searched again. 

The general logic that the MISPHunter executes is as follows:

```
for each event with an enabled active misphunter-seed...
process_seeds -> for each seed in that event:
  find the hosts related to that seed search 

  Each host becomes a skeleton of a misphunter-host object with the bare
  minimum of an IP and a blacklist boolean. This skeleton object is created by 
  trying the following things in order:
    1. Check if a misphunter-host object with this IP exists in this event.
    2. Check if a misphunter-host object with this IP exists anywhere in the 
      MISP instance. If so, clone it and save it here.
    3. If no existing object can be found, make API calls to all active 
      misphunter-host services and build a new object.
  This skeleton object is then sent to the "stage" for further processing.

  We then begin processing all objects in the stage.
  While processing an object, new objects may be added to the stage.
  Each object on the stage is processed until there are no more objects left.

  misphunter-host objects are processed by the process_host function.
    extract domains, IPs, emails, URLs, and certificates from the raw JSON 
      responses sent by the service add those details as attributes to the 
      misphunter-host object
    compare the full json dictionary returned by the service with the last 
      time it was retrieved. Save the raw JSON as an attachment within the 
      misphunter-host object. Mark any keys that were added/removed/modified 
      inside the attachment's comments.
    If any attributes are extracted that are deemed "pivotable" (e.g. a
      certificate hash), create skeleton objects for them and push to the stage.

  misphunter-cert objects are processed by the process_cert function.
    NOTE: these pivots currently require censys-v1 to be active.
    extract important information and potential IOCs from the certificate.
    search for other IPs using the same certificate.
    If < 2 or > misphunter.cert_pivot_threshold hosts are found associated with
      this certificate, automatically blacklist it to save future API queries.
    If additional IPs are found that have not already been processed for this
      event, get or create their corresponding misphunter-host objects and 
      push those to the stage.

graph appropriate relationships between newly created misphunter objects

tag/untag important things that are newer/older than --new-discovery-threshold 
  (default 72 hrs) for easy visibility

automatically disable things that shouldn't be pivoted on again (like certs
  returning only 1 host) that aren't already blacklisted.
```

If you want to force a particular search to be processed again, just delete the `last-run` attribute from its corresponding 
`misphunter-seed` and re-run `misphunter.py`.

If you want to prevent a particular search from running again in the future, just change the `enabled` attribute from 
`1` to `0`.

### Example seed after running

![image](https://user-images.githubusercontent.com/6147794/132044208-8c859fab-7219-4311-8d75-54ad5d0f435e.png)

### Example host object after running

![image](https://user-images.githubusercontent.com/6147794/132044399-3ac74c72-3c7b-4837-bc55-172b34d36565.png)

### Example certificate object after running

![image](https://user-images.githubusercontent.com/6147794/132556830-fbe63a36-4a76-4f2a-b4bc-912599783bf2.png)

### Example graph after running

![image](https://user-images.githubusercontent.com/6147794/132046748-aa067f15-5dc6-4333-ae86-85072f1665f6.png)

## Installing as a service

Make sure everything lives in /opt/MISPHunter/

To install the service do the following as root:
```
cp /opt/MISPHunter/misphunter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now misphunter
systemctl start misphunter
systemctl status misphunter
```

This should now start whenever you start your server, and if it crashes (which at some point it likely will),
it will automatically restart itself.
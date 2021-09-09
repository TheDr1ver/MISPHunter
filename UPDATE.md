# Where I Left Off

```
misphandler.py", line 119, in build_misphunter_cert
    parsed_data = raw_data['parsed']
KeyError: 'parsed'
```

# Update Plan

There was an idea behind this update, but instead of making things simpler I managed
to waste 9 hours making them worse.

I might revisit this at another time, but right now I feel like my efforts might
be better spent in tweaking the existing scripts that I know actually work.

Here was the idea for the improved readablility/simplicity of the flow:

- Get emabled seeds & corresponding events. This results in `results = {'event_id': [<misphunter-seed>]}`
- For each event, process seeds
- For each seed, run search & generate `misphunter-host` objects. Do not add these objects to the event yet. 
    Save new and updated objects to `mh.new_objects`. Return event
- For each `misphunter-*` object in `mh.new_objects`, process the object according to the type:
    extract IOCs, compare dicts, remove from `mh.new_objects`, add object UUID to 
    `mh.updated_objects`, update & return event.
- ^^^ *Here's where it breaks down.* If you don't update those objects or add them to the event before continuing,
    you have no way of knowing which ones you've already cloned/created/updated and added to `mh.new_objects`,
    so you end up with a lot of duplicates and wasted API queries. (e.g. Shodan returns 192.168.1.100, Censys returns
    the same IP during seed processing. Censys doesn't know about Shodan making the 192.168.1.100 object because it
    hasn't been added to the event yet. As a result you end up making 2 separate objects before they actually get
    processed and added.)
- Run a generator against `mh.new_objects`. Depending on the type of object, process it accordingly.
    If it's blacklisted, skip it. If the UUID has already been processed, skip it. Run this until there's
    nothing else to update. Each time, update/return event.
- Find enabled objects from the event that are not in mh.updated_objects and send them through the same process.
- Auto-relate objects. Update/return event.
- Auto-tag/untag newness. Update/return event.
- Next event!

There's got to be a better/cleaner way to do this instead of the rat's nest of nested functions I currently
have in process_seeds(), I'm just burned out and can't seem to wrap my head around it at the moment without 
making things worse.
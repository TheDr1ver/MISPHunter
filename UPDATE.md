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

- Get enabled seeds & corresponding events. This results in `results = {'event_id': [<misphunter-seed>]}`
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

# Let's Rethink This

- Get enabled seeds & corresponding events. This results in `results = {'event_id': [<misphunter-seed>]}`
- For each event, process seed objects

## Two modes for objects

### Stage_Object()
- Staging an object is handled in the following manner
    - Check event for existing object. If object exists, update timestamps, update object, & retrieve event.
    - If object does not exist, check server for object within `{update_threshold}` age. Clone object, update timestamps,
        update object, & add to/update event & then retrieve event.
    - If object does not exist anywhere, create object, save new object to event, retrieve updated event.
    - Check if the object about to be staged is blacklisted, and if so, skip it.
    - Finally, add the resulting object to `mh.staged_objects`

### Process_Object()
- Loop through `mh.staged_objects`
    - Process each staged object based on the object type it is
        - `misphunter-seed`
            - search gets run, IPs get returned and added to processing object
            - various pivot types are pulled - in this case, `found-ip` gets
                passed to `stage_object(value=ip, object_name="misphunter-host")`
            - Follow `stage_object()` procedures
        - `mipshunter-host`
            - host is inspected, IOCs extracted, Dict Compare
            - various pivot types are pulled - in this case, `extracted-certificate` gets
                passed to `stage_object(value=cert, object_name="misphunter-cert")`
            - Follow `stage_object()` procedures
        - `misphunter-certificate`
            - cert is inspected, related IPs are retrieved
            - Auto-Blacklist is run to make sure too many IPs weren't pulled. If blacklisted, skip to update section.
            - various pivot types are pulled - in this case, `cert-ip` gets passed to
                `stage_object(value=ip, object_name="misphunter-host)`
            - Follow `stage_object()` procedures
    - process object is updated
    - process object is removed from `mh.staged_objects`
    - process object UUID is added to `mh.processed_object_uuids`
- Continue to process objects, looping through continually updated `mh.staged_objects` until finished
- ^^^ The key is right before an object is moved to `mh.staged_objects` it MUST be pushed to the instance, 
    and the event MUST be updated.

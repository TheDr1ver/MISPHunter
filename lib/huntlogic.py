import logging, logging.handlers
import sys

from pprint import pformat
from time import time

from . import helper, misphandler

###################
#### 2-Stage Functions
###################

def extract_pivots(mh, obj, event):
    pivot_map = mh.obj_pivot_mapping[obj.name]
    for pivot_rel, pivot_obj_name in pivot_map.items():
        pivot_attrs = misphandler.get_all_attrs_by_rel(obj, pivot_rel)
        if len(pivot_attrs) > 0:
            mh.logger.info(f"Extracting {pivot_rel} pivots from {obj.name} "
                f"object [{obj.uuid}] and sending to stage...")
        for attr in pivot_attrs:
            if pivot_obj_name in mh.obj_index_mapping:
                pivot_obj_index_rel = mh.obj_index_mapping[pivot_obj_name]
                event = stage_object(mh, pivot_obj_name, pivot_obj_index_rel, attr.value, event)
            else:
                mh.logger.info(f"No index mapped in obj_index_mapping for "
                    f"{pivot_obj_name} object type. Skipping pivot "
                    f"{attr.value}!")
    return event

def process_cert(mh, cert, event):
    mh.logger.info(f"Processing cert {cert.uuid} from stage!")

    # Check for basic requirements
    cert_hash = misphandler.get_attr_val_by_rel(cert, 'cert-sha256')
    if not cert_hash:
        mh.logger.error(f"No cert_hash found associated with cert object "
            f"{cert.uuid}. Skipping seed!")
        return event

    # Enrich Cert Details
    if not hasattr(cert, 'event_id'):
        cert.event_id = str(event.id)
    cert = helper.enrich_cert_obj(mh, cert)

    # Even if something fails it should always return the original cert object
    # at a minium. So no need to check if it returned False.

    # Since cert object was successfully updated, we need to get a fresh copy
    # of event to return going forward
    updated_event = misphandler.get_event(mh, event.id)
    if not updated_event:
        mh.logger.error(f"Failed getting event {event.id}... This "
            f"shouldn't happen if your MISP server is alive. Skipping "
            f"cert {cert.uuid}!")
        return event
    event = updated_event

    # Check if blacklisted
    blacklisted = misphandler.get_attr_val_by_rel(cert, 'blacklisted')
    if int(blacklisted) == 1:
        mh.logger.info(f"{cert.name} object {cert.uuid} is blacklisted. "
            f"Skipping pivots!")
        return event

    # Collect pivot objects to send to stage for future processing
    event = extract_pivots(mh, cert, event)

    mh.logger.info(f"Finished processing host {cert.uuid}!")

    return event

def process_host(mh, host, event):
    mh.logger.info(f"Processing host {host.uuid} from stage!")

    # Enrich the host object by extracting IOCs, comparing changes, etc.
    if not hasattr(host, 'event_id'):
        host.event_id = str(event.id)
    host = helper.enrich_host_obj(mh, host)

    if not host:
        mh.logger.error(f"Something went wrong processing host {host.uuid}!"
            f"Skipping further processing!")
        return event

    # Since host object was successfully updated, we need to get a fresh copy 
    # of event to return going forward
    updated_event = misphandler.get_event(mh, event.id)
    if not updated_event:
        mh.logger.error(f"Failed getting event {event.id}... This "
            f"shouldn't happen if your MISP server is alive. Skipping "
            f"host {host.uuid}!")
        return event
    event = updated_event

    # Check if blacklisted
    blacklisted = misphandler.get_attr_val_by_rel(host, 'blacklisted')
    if int(blacklisted) == 1:
        mh.logger.info(f"{host.name} object {host.uuid} is blacklisted. "
            f"Skipping pivots!")
        return event

    # Collect pivot objects to send to stage for future processing
    event = extract_pivots(mh, host, event)

    mh.logger.info(f"Finished processing host {host.uuid}!")

    return event

def process_stage_object(mh, obj, event):
    if obj.name == "misphunter-seed":
        event = process_seed(mh, obj, event)
    # run search if ready, update timestamps, save found-hosts as 
    #   misphunter-host skeletons per mh.obj_pivot_mapping
    # stage_object for each pivot object
        
    elif obj.name == "misphunter-host":
        event = process_host(mh, obj, event)
        # enrich_host is run:
        #   host is inspected for newness, 
        #   API hit if necessary, IOCs extracted, Dict Compare
        # host_obj is updated (it already exists in this event because 
        #   it was in staging)
        # event is updated
        # various pivot types are pulled & staged
        #   in this case, 'found-host' value gets passed to 
        #   event = stage_object(mh, 'misphunter-host', 'host-ip', value, event)
        # event returned
      
    elif obj.name == "misphunter-cert":
        event = process_cert(mh, obj, event)

    else:
        mh.logger.warning(f"Not sure how to  process {obj.name} object "
            f"{obj.uuid} - removing from stage and continuing...")

    # Remove the object from the stage after it's been processed
    mh.logger.debug(f"Removing {obj.name} {obj.uuid} from stage.")
    mh.event_staged_objects.remove(obj)

    mh.logger.debug(f"Adding {obj.name} {obj.uuid} to processed list.")
    mh.event_processed_object_uuids.append(obj.uuid)
    if mh.debugging:
        helper.log_stage_details(mh)

    return event

def process_seed(mh, seed, event):
    mh.logger.info(f"Processing seed {seed.uuid} from stage!")
    run_search, seed = misphandler.check_timer(mh, seed)
    # If timer checks don't pass, remove this object from the stage and 
    # skip this seed
    if not run_search:
        return event
    
    # If run_search = True we should update the search last_seen values
    index_attr = misphandler.get_attr_obj_by_rel(seed, 
        mh.obj_index_mapping[seed.name])
    misphandler.update_timestamps(mh, index_attr)
    
    # Also make sure we have the latest event after the check_timer updates
    updated_event = misphandler.get_event(mh, event.id)
    if not updated_event:
        mh.logger.error(f"Failed getting event {event.id}... This "
            f"shouldn't happen if your MISP server is alive. Skipping "
            f"seed {seed.uuid}!")
        return event
    event = updated_event

    # Check for basic requirements
    service = misphandler.get_attr_val_by_rel(seed, 'service')
    if not service:
        mh.logger.error(f"No service found associated with seed object "
            f"{seed.uuid}. Skipping seed!")
        return event

    search = misphandler.get_attr_val_by_rel(seed, 'search-string')
    if not search:
        mh.logger.error(f"No search string found associated with seed object "
            f"{seed.uuid}. Skipping seed!")
        return event

    # Check if seed_service is activated
    if service not in mh.host_seed_services:
        mh.logger.info(f"{service} is not currently active. Skipping seed "
            f"{seed.uuid}!")
        return event

    mh.logger.debug(f"Timer checks have passed! Processing seed for "
        f"[{service}] - {search}...")

    # Run search and get resulting IPs
    ips = helper.run_host_seed(mh, search, service)
    if len(ips) <= 0:
        mh.logger.info(f"No IPs were found running {service} search {search}. "
            f"Skipping seed!")
        return event
    
    new_host = False
    # Add all found IPs to seed first
    mh.logger.info(f"Found {len(ips)} IPs while searching {service} with seed "
        f"{seed.uuid}!\n\t\t{ips}")
    # Collect existing IPs
    found_hosts = []
    ip_attrs = misphandler.get_all_attrs_by_rel(seed, 'found-host')
    for attr in ip_attrs:
        if attr.value not in found_hosts:
            found_hosts.append(attr.value)

    # Process IPs returned by the search
    mh.logger.info(f"Adding new IPs and updating timestamps for prexisting ones.")
    for ip in ips:
        if ip not in found_hosts:
            # Add new IPs
            found_hosts.append(ip)
            mh.logger.info(f"Adding found IP {ip} to seed object {seed.uuid}.")
            new_host = seed.add_attribute('found-host', ip, type='ip-dst',
                disable_correlation=False, to_ids=False, pythonify=True)
            misphandler.update_timestamps(mh, new_host)
        else:
            # Update timestamps for existing IPs that were returned
            for attr in ip_attrs:
                if attr.value == ip:
                    misphandler.update_timestamps(mh, attr)

    # If any new IPs were found, update the seed object
    if new_host:
        updated_seed = misphandler.update_existing_object(mh, seed)
        # Make sure it updated properly
        if not updated_seed:
            mh.logger.error(f"Error attempting to update seed object "
                f"{seed.uuid} with new hosts: {ips}")
            mh.logger.error(f"Skipping seed object {seed.uuid}!")
            return event
        seed = updated_seed
    
    # Get latest updated version of event
    updated_event = misphandler.get_event(mh, event.id)
    # Make sure we got the latest event
    if not updated_event:
        mh.logger.error(f"Failed getting event {seed.event_id}... This "
            f"shouldn't happen if your MISP server is alive. Skipping "
            f"seed {seed.uuid}!")
        return event
    event = updated_event

    # Collect pivot objects to send to stage for future processing
    event = extract_pivots(mh, seed, event)

    mh.logger.info(f"Finished processing seed {seed.uuid}!")

    return event

def set_the_stage(mh, objs, event):
    mh.logger.info(f"Setting the stage with objects...")
    for obj in objs:
        # get value of object's "index" or unique value
        object_name = obj.name
        if obj.name not in mh.obj_index_mapping:
            mh.logger.error(f"{obj.name} object not a known type for pivots. Skipping!")
            # TODO update stats for skipped stage objects
            continue
        pivot_rel = mh.obj_index_mapping[obj.name]
        value = misphandler.get_attr_val_by_rel(obj, pivot_rel)
        if not value:
            mh.logger.error(f"{obj.name} object {obj.uuid} had no {pivot_rel} "
                f"pivot value. Not staging object!")
            # TODO update stats for skipped stage objects
            continue

        event = stage_object(mh, object_name, pivot_rel, value, event)

    mh.logger.info(f"Finished setting the stage!")
    return event

def stage_object(mh, object_name, pivot_rel, value, event):
    mh.logger.info(f"Staging {object_name} object using value {value}...")
    found_obj = False
    cloned_obj = False
    new_obj = False
    # Look to see if the object exists in the event
    relevant_objects = event.get_objects_by_name(object_name)
    for obj in relevant_objects:
        relevant_attrs = obj.get_attributes_by_relation(pivot_rel)
        if found_obj:
            break
        for attr in relevant_attrs:
            if attr.value == value:
                found_obj = obj
                pivot_attr = attr
                break

    # If we found a valid object already attached to this event: 
    if found_obj:
        mh.logger.info(f"Found existing {object_name} object [{found_obj.uuid}] "
            f"for event {event.info}... Using that!")
        updated_obj = found_obj
        updated_obj.is_new = False
        updated_obj.is_clone = False

    # If we didn't find a suitable object already in this event...
    else:
        # Look to see if the object exists in the instance, using the 
        #   new_discovery_threshold window
        # If so:
        #   clone object
        #   update timestamps for pivot_rel attr matching value
        mh.logger.info(f"{object_name} object with {pivot_rel} value of "
            f"{value} was not found in the current event.\n\tSearching the "
            f"rest of the MISP instance for appropriate objects...")
        cloned_obj = misphandler.search_recent_updated_objects(mh, event, 
            object_name=object_name, value=value, rel=pivot_rel, 
            timeframe=mh.new_discovery_threshold)

    # If it was successfully cloned just now...
    if cloned_obj:
        mh.logger.info(f"Successfully cloned {object_name} object "
            f"[{cloned_obj.uuid}] into event {event.info}... Using that!")
        # ...all the timestamps will have just been updated
        # add the cloned object to MISP event
        updated_obj = event.add_object(cloned_obj)
        # update MISP event
        updated_event = misphandler.update_event(mh, event)
        if updated_event:
            # set updated event for return
            event = updated_event
        updated_obj.is_new = False
        updated_obj.is_clone = True
        
    if not cloned_obj and not found_obj:
        # Object does not exist anywhere in this instance
        # create bare minimum, brand new MISP object
        new_obj = misphandler.create_obj_skeleton(mh, object_name=object_name,
            value=value, rel=pivot_rel)
        mh.logger.info(f"Succesfully created new {object_name} object "
            f"[{new_obj.uuid}] into event {event.info}!")
        # add the newly-built object to MISP event
        updated_obj = event.add_object(new_obj)
        # Update MISP event
        updated_event = misphandler.update_event(mh, event)
        if updated_event:
            # set updated event for return
            event = updated_event
        updated_obj.is_new = True
        updated_obj.is_clone = False

    if not updated_obj:
        mh.logger.warning(f"Something went wrong staging {object_name} object "
            f"using value {value}. This should be investigated\n")
        return event
    
    # Check if the object is blacklisted
    blacklisted = misphandler.get_attr_val_by_rel(updated_obj, 'blacklisted')
    if int(blacklisted) == 1:
        mh.logger.info(f"{object_name} object is blacklisted! Not adding it "
            f"to the processing stage!\n")
        return event

    # If the object has been updated and it's not blacklisted,
    # check if it's already been processed
    if updated_obj.uuid in mh.event_processed_object_uuids:
        mh.logger.info(f"{object_name} object [{updated_obj.uuid}] has "
            f"already been processed! Not adding it to the processing stage!\n")
        return event

    # Make sure this object isn't already staged for processing...
    staged_uuids = []
    for obj in mh.event_staged_objects:
        if obj.uuid not in staged_uuids:
            staged_uuids.append(obj.uuid)

    if updated_obj.uuid not in staged_uuids:
        mh.logger.info(f"Successfully added {object_name} object "
            f"[{updated_obj.uuid}] to the processing stage!\n")
        # if mh.debugging:
        #     mh.logger.debug(f"Staged object info: \n\n"
        #         f"{pformat(updated_obj.to_dict())}")
        mh.event_staged_objects.append(updated_obj)
    else:
        mh.logger.info(f"{object_name} object [{updated_obj.uuid}] is "
            f"already staged for processing!\n")

    return event

###################

def auto_blacklist(mh, event):
    
    mh.logger.debug(f"Determining if any objects should be automatically blacklisted based on their pivot results.")
    all_certs = event.get_objects_by_name('misphunter-cert')
    for cert in all_certs:
        cert = misphandler.blacklist_check_cert(mh, cert)
    return event

def process_new_tags(mh, event):

    mh.logger.info(f"Tagging new discoveries and untagging old ones.")

    tag_dict = {
        "attachment": "misphunter:new-discovery=\"service-updated\"",
        "domain": "misphunter:new-discovery=\"domain\"",
        "ip": "misphunter:new-discovery=\"host\"",
        "sha256": "misphunter:new-discovery=\"malware\"",
        "url": "misphunter:new-discovery=\"url\"",
        "whois": "misphunter:new-discovery=\"whois-record\"",
        "x509": "misphunter:new-discovery=\"certificate\"",
    }

    added_tags = []
    removed_tags = []

    new_tags = []

    new_time = int(time()) - (int(mh.new_discovery_threshold) * 60 * 60)

    for obj in event.Object:
        for attr in obj.Attribute:
            # Highlight empty json blobs
            if attr.value == "99914b932bd37a50b983c5e7c90ae93b.json":
                attr_tags = []
                attr_tags = misphandler.check_tags(attr)
                if "EMPTY-JSON" not in attr_tags:
                    mh.logger.info(f"Found empty JSON file response. Consider "
                        f"blacklisting {obj.name} [{obj.uuid}]!")
                    misphandler.tag(mh, attr, "EMPTY-JSON")

            # If first_seen isn't set we don't know how new this really is. 
            # Ignore it.
            if not hasattr(attr, 'first_seen'):
                continue

            # If this isn't something we're supposed to tag (like a comment or 
            # attachment), ignore it.
            attr_type = attr.type
            attr_type_part = attr_type.split("-")[0]
            if attr_type_part not in tag_dict:
                continue

            attr_tags = misphandler.check_tags(attr)
            first_seen = int(attr.first_seen.timestamp())
            if first_seen >= new_time:

                mh.logger.info(f"Found attribute created within the last "
                    f"{mh.new_discovery_threshold} hours! - {attr.value}\n\t"
                    f"first_seen: {first_seen} {mh.new_discovery_threshold} hrs ago: {new_time}")

                tag = tag_dict[attr_type_part]

                # if this tag exists already for this attribute, no need to 
                # tag it again.
                if tag not in attr_tags:
                    # misphandler.tag(mh, attr, tag)
                    tup = (attr, tag)
                    added_tags.append(tup)
                    # Track stats
                    helper.track_stats_tags_added(mh, tag, attr)
                else:
                    mh.logger.debug(f"Attribute {attr.uuid} is new, but already has tag {tag}!")

                if tag not in new_tags:
                    new_tags.append(tag)
            else:
                for tag in attr_tags:
                    if tag.startswith("misphunter:new-discovery="):
                        mh.logger.info(f"Removing new-discovery tag {tag} from old attribute {attr.uuid}.\n\t"
                            f"attribute was first_seen {first_seen} and we need it to be newer than {new_time}.")
                        # misphandler.untag(mh, attr, tag)
                        tup = (attr, tag)
                        removed_tags.append(tup)
                        # Track stats
                        helper.track_stats_tags_removed(mh, tag, attr)

    # Apply untags first so they appear below new tags
    for tag in removed_tags:
        misphandler.untag(mh, tag[0], tag[1])
    # Then apply new tags
    for tag in added_tags:
        misphandler.tag(mh, tag[0], tag[1])

                
    event_tags = misphandler.check_tags(event)
    # Add tags to the event for every new attribute we discovered.
    for tag in new_tags:
        if tag not in event_tags:
            mh.logger.info(f"Adding {tag} tag to event {event.id}.")
            misphandler.tag(mh, event, tag)
            # Track stats
            helper.track_stats_tags_added(mh, tag, event)

    # Remove tags from the event if it was previously tagged with something 
    # that's old now.
    for tag in event_tags:
        if tag.startswith("misphunter:new-discovery="):
            if tag not in new_tags:
                mh.logger.info(f"Removing {tag} tag from event {event.id}.")
                misphandler.untag(mh, event, tag)
                # Track stats
                helper.track_stats_tags_removed(mh, tag, event)

    event = misphandler.get_event(mh, str(event.id))

    return event

def process_relationships(mh, event):
    # Organize events into rel_index so it's easier to process relationships
    mh.logger.info(f"Processing relationships for event [{event.id}] - {event.info}")
    total_new_rels = 0
    rel_index = helper.organize_event_objects(mh, event)
    # Relate certs to IPs they were found on
    rel_index, num_new_rels = helper.build_cert_host_rels(mh, event, rel_index)
    total_new_rels += num_new_rels
    # Relate seeds to hosts those seeds discovered
    rel_index = helper.build_seed_host_rels(mh, event, rel_index)
    total_new_rels += num_new_rels

    # Update the event to finalize the relationships
    if total_new_rels > 0:
        mh.logger.info(f"{total_new_rels} new relationships were built!")
        updated_event = misphandler.update_event(mh, event)
        if not updated_event:
            mh.logger.error(f"Error updating object relationships in "
                f"{event.info}. Leaving event as-is.")
            return event
        event = updated_event
    else:
        mh.logger.info(f"No new relationships were found. Leaving event as-is.")

    return event

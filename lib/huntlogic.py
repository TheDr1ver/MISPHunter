import logging, logging.handlers
import sys

from pprint import pformat
from time import time

from . import helper, misphandler

'''
def get_logger():
    
    _log = logging.getLogger(__name__)
    mh.logger.setLevel(logging.DEBUG)
    mh.logger.handlers = []
    log_loc = "./misp-hunter.log"
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(funcName)s ln %(lineno)d - %(levelname)s - %(message)s")
    
    file_handler = logging.handlers.RotatingFileHandler(filename=log_loc, mode='a', maxBytes=30000000, backupCount=10)
    file_handler.setFormatter(formatter)
    mh.logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    mh.logger.addHandler(console_handler)
    
    return _log
'''

# _log = helper.get_logger()

###################
#### Stage 2 Functions
###################

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
            mh.logger.error(f"{obj.name} object had no pivot value. Skipping!")
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
        # update timestamps for pivot_rel attr matching value
        misphandler.update_timestamps(mh, pivot_attr)
        # obj = update object in MISP
        updated_obj = misphandler.update_existing_object(mh, found_obj)
        # retrieve updated event
        event = misphandler.get_event(mh, event.id)
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
    # If run_search is True, it means the seed object was updated.
    # We need to get a fresh copy of event to return going forward
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

def process_cert(mh, cert, event):
    mh.logger.info(f"Processing cert {cert.uuid} from stage!")

    return event


def process_host(mh, host, event):
    mh.logger.info(f"Processing host {host.uuid} from stage!")

    # Enrich the host object by extracting IOCs, comparing changes, etc.
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

    # Collect pivot objects to send to stage for future processing
    event = extract_pivots(mh, host, event)

    mh.logger.info(f"Finished processing host {host.uuid}!")

    return event

###################

def auto_blacklist(mh, event):
    
    mh.logger.debug(f"Determining if any objects should be automatically blacklisted based on their pivot results.")
    all_certs = event.get_objects_by_name('misphunter-cert')
    for cert in all_certs:
        cert = misphandler.blacklist_check_cert(mh, cert)
    return event
'''
def cert_pivot(mh, host_obj, event, seed):

    host_ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
    service = misphandler.get_attr_val_by_rel(seed, 'service')
    host_certs = []
    all_cert_data = []
    
    # Get all "extracted-certificate" attributes for this host
    extracted_certs = host_obj.get_attributes_by_relation("extracted-certificate")

    # Add all SHA256 cert values for this specific host to host_certs list
    for cert_attr in extracted_certs:
        if cert_attr.value not in host_certs:
            host_certs.append(cert_attr.value)

    if len(host_certs) > 0:
        mh.logger.info(f"Found {len(host_certs)} new cert(s) for pivoting in new object: "\
            f"{pformat(host_certs)}")

    # Pivot on all the hashes associated with this specific host
    for cert_hash in host_certs:
        new_cert_obj = True
        mh.logger.info(f"Pivoting on cert {cert_hash}...")
        # Returns MISPObject misphunter-cert
        cert_data = helper.search_cert_data(mh, cert_hash, host_obj, event)
        if not cert_data:
            mh.logger.error(f"Something went wrong attempting to get certificate data. Skipping cert {cert_hash} entirely!")
            continue

        # check if this cert is blacklisted
        blacklisted = misphandler.get_attr_val_by_rel(cert_data, 'blacklisted')
        if int(blacklisted) == 1:
            mh.logger.info(f"misphunter-cert {cert_hash} [{cert_data.uuid}] is marked as blacklisted. Skipping!")
            continue

        # Check if this cert object is new to this event or not
        for existing_obj in mh.event_certs:
            if cert_data.uuid == existing_obj.uuid:
                mh.logger.info(f"This certificate is not new to this event. Setting new_cert_obj to False.")
                new_cert_obj = False

        # Check cert_data timestamp - if less than update threshold, update IPs.
        update_ips = helper.check_update_threshold(mh, cert_data)
        if update_ips or new_cert_obj:
            if update_ips:
                mh.logger.debug(f"check_update_threshold() returned True - searching again for IPs!")
            if new_cert_obj:
                mh.logger.debug(f"new_cert_obj is set to True, which means this cert is new to this event, which means "
                    "we're once again searching for related IPs!")
            # Find IPs associated with this cert
            if not hasattr(cert_data, 'event_id'):
                cert_data.event_id = event.id
            cert_data = helper.search_cert_hosts(mh, cert_data, host_ip)
            blacklisted = misphandler.get_attr_val_by_rel(cert_data, 'blacklisted')
        
        # Update object/event
        if new_cert_obj:
            mh.logger.info(f"misphunter-cert object {cert_data.uuid} is apparently new to event {event.id}. "
                "Updating event!")
            event.add_object(cert_data, pythonify=True)
            updated_event = misphandler.update_event(mh, event)
            if not updated_event:
                mh.logger.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object.")
                mh.logger.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
            else:
                event = updated_event
        else:
            mh.logger.info(f"misphunter-cert object {cert_data.uuid} is NOT new to event {event.id}. "
                f"Updating object first...")
            updated_object = misphandler.update_existing_object(mh, cert_data)
            if not updated_object:
                mh.logger.error(f"Error updating existing cert-object {cert_data.uuid} in event {event.id}. Returned "
                    "False instead of MISPEvent Object.")
                mh.logger.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
                continue
            else:
                cert_data = updated_object
                mh.logger.info(f"...then getting a fresh copy of event {event.id} and updating it!")
                updated_event = misphandler.get_event(mh, cert_data.event_id)
                if not updated_event:
                    mh.logger.error(f"Simply GETTING event {event.id} FAILED. Returned False instead of MISPEvent Object. "
                        "Using pre-existing event going forward.")
                    mh.logger.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
                    continue
                else:
                    event = updated_event

        # Add all finished cert_data objects to a big list for IP processing
        # taking care to ignore blacklisted events
        if cert_data not in all_cert_data:
            if not int(blacklisted) == 1:
                all_cert_data.append(cert_data)
            else:
                mh.logger.debug(f"cert object {cert_data.uuid} is blacklisted. Not processing associated IPs.")

    mh.logger.info(f"Finished processing certs for host object {host_obj.uuid}.")

    host_ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')

    event = process_cert_ips(mh, all_cert_data, seed, event, host_ip)

    mh.logger.debug(f"Finished certificate pivoting!")
    return event

def process_cert_ips(mh, all_cert_data, seed, event, host_ip):
    # ignore IPs arleady in this event to avoid getting caught in a loop
    existing_event_hosts = []
    for host in mh.event_hosts:
        ip = misphandler.get_attr_val_by_rel(host, 'host-ip')
        if ip not in existing_event_hosts:
            existing_event_hosts.append(ip)

    for cert_obj in all_cert_data:
        cert_ips = []
        cert_ip_attrs = misphandler.get_all_attrs_by_rel(cert_obj, 'cert-ip')
        for cert_ip_attr in cert_ip_attrs:
            cert_ip = cert_ip_attr.value
            if cert_ip not in cert_ips:
                # Ignore the IP that we just processed to avoid an infinite loop
                if cert_ip != host_ip:
                    if cert_ip not in existing_event_hosts:
                        cert_ips.append(cert_ip)
                else:
                    mh.logger.debug(f"Ignoring {cert_ip} associated with this cert because it's already been processed.")
        if len(cert_ips) <= 0:
            mh.logger.debug(f"No IPs were found associatd with misphunter-cert object {cert_obj.uuid}. Checking next cert!")
            continue
        else:
            updated_event = process_hosts(mh, event, seed, cert_ips)
            if not updated_event:
                mh.logger.error(f"Something went wrong running process_hosts() for cert_ips: {cert_ips}. Skipping cert_obj {cert_obj.uuid}!")
                mh.logger.debug(f"Using previous iteration of event...")
                mh.logger.debug(f"FIGURE OUT WHY process_hosts() FAILED AGAINST THE ABOVE GROUP OF cert_ips!")
                continue
            else:
                event = updated_event
    mh.logger.info(f"All {len(all_cert_data)} cert objects processed for {host_ip}. Updating event and MOVING ON!")
    # Update event before exiting the routine
    updated_event = misphandler.update_event(mh, event)
    if not updated_event:
        mh.logger.error(f"Something went wronng trying to update the final MISPEvent of the process_cert_ips() routine!")
        mh.logger.debug(f"returning untouched event that was sent to the process_cert_ips routine. FIGURE IT OUT!")
    else:
        event = updated_event
    return event

def process_host_seed(mh, seed, event):
    mh.logger.info(f"Geneating hosts from seed {seed.uuid}")
    seed_service = misphandler.get_attr_val_by_rel(seed, 'service')
    seed_search = misphandler.get_attr_val_by_rel(seed, 'search-string')
    ips = helper.run_host_seed(mh, seed_search, seed_service)

    if len(ips) <= 0:
        mh.logger.error(f"No IPs were found running {seed_service} search {seed_search}.Skipping seed!")
        return False, False

    # Add all found IPs to seed first
    mh.logger.debug(f"Found {len(ips)} IPs while searching {seed_service} with seed {seed.uuid}!")
    seed_found_ips = []
    seed_ip_attrs = misphandler.get_all_attrs_by_rel(seed, 'found-host')
    for attr in seed_ip_attrs:
        if attr.value not in seed_found_ips:
            seed_found_ips.append(attr.value)
    for ip in ips:
        if ip not in seed_found_ips:
            seed_found_ips.append(ip)
            mh.logger.info(f"Adding found IP {ip} to seed object {seed.uuid}.")
            attr = seed.add_attribute('found-host', ip, type='ip-dst', disable_correlation=False, 
                to_ids=False, pythonify=True)
            misphandler.update_timestamps(mh, attr)
        else:
            for attr in seed_ip_attrs:
                if attr.value == ip:
                    misphandler.update_timestamps(mh, attr)

    # Update Object
    updated_seed = misphandler.update_existing_object(mh, seed)
    if not updated_seed:
        mh.logger.error(f"Error attempting to update seed object {seed.uuid} with new found-ips {ips}.")
        return False, False
    
    seed = updated_seed

    # Add Object UUID to mh.processed_objects
    if seed.uuid not in mh.event_processed_object_uuids:
        mh.event_processed_object_uuids.append(seed.uuid)

    # Return search results and update seed
    return ips, seed
    
def process_seeds(mh, seeds, event):
    mh.logger.info(f"Processing {len(seeds)} seeds...")
    for seed in seeds:
        mh.run_search = False
        # Check timer for each seed to make sure we're not running prematurely
        # Also sets self.run_search to True if it's time to run the seed search again
        seed = misphandler.check_timer(mh, seed)
        if not mh.run_search:
            continue
        seed_service = misphandler.get_attr_val_by_rel(seed, 'service')
        if not seed_service:
            mh.logger.error(f"No service found associated with seed object {seed.uuid}. Skipping seed!")
            continue
        seed_search = misphandler.get_attr_val_by_rel(seed, 'search-string')
        if not seed_search:
            mh.logger.error(f"No search string found associated with seed object {seed.uuid}. Skipping seed!")
            continue
        mh.logger.debug(f"Timer checks have passed. Processing seed for [{seed_service}] - {seed_search}...")
        # Check if seed_service is active host_seed_service type (e.g. censys-v2, shodan)
        if seed_service in mh.host_seed_services:
            mh.logger.debug(f"{seed_service} service is used to generate host seeds.")
            ips, seed = process_host_seed(mh, seed, event)
            # if returned false, no IPs were found or something failed and we should skip
            if not ips:
                continue

            # Collects host_objects into mh.event_new_objects for further processing.
            event = collect_host_objects(mh, ips, event)
    return event

def collect_host_objects(mh, ips, event):
    mh.logger.info(f"Collecting host objects for {len(ips)} discovered hosts: {ips}.")
    blocks = misphandler.get_local_blocks(mh, event)
    mh.logger.debug(f"All blocks: {blocks}")

    # Loop through each IP discovered
    for ip in ips:
        # Check IP against local and gloabl blocks
        if helper.check_block(mh, ip, blocks):
            continue
        mh.logger.info(f"Processing IP {ip}")
        # Get existing misphunter-host object or create new one
        host_obj = misphandler.get_host_obj(mh, ip, event)
        # NOTE: host_obj returns .is_new=True if it's a newly built host object or a clone
        #   returns .is_new=False if it already existed in this event
        if not host_obj:
            mh.logger.error(f"After processing IP {ip} with get_host_obj() something still managed to go wrong. "
                "Skipping this host.")
            continue

        if host_obj.uuid not in mh.event_new_object_uuids:
            mh.logger.info(f"Collected host_obj {host_obj.uuid} for further processing. Adding to mh.event_new_objects!")
            mh.event_new_object_uuids.append(host_obj.uuid)
            mh.event_new_objects.append(host_obj)

        # If we don't process the host now and it shows up again in the next seed search, it'll create a duplicate object
        event = process_host(mh, host_obj, event)

    mh.logger.info(f"Found {len(mh.event_new_object_uuids)} hosts total.")        
    return event

def process_event_new_objects(mh, event):

    for obj in mh.event_new_objects:
        if obj.name == "misphunter-host":
            if obj.uuid not in mh.event_processed_object_uuids:
                mh.logger.debug(f"Found new {obj.name} object to process!")
                # process_host is where you extract IOCs, compare dicts, 
                # then add it to the event or update it if it already exists
                event = process_host(mh, obj, event)
            
        elif obj.name == "misphunter-cert":
            if obj.uuid not in mh.event_processed_object_uuids:
                mh.logger.debug(f"Found new {obj.name} object to process!")
                mh.logger.debug(f"Normally I'd be processing {obj.name} object {obj.uuid} now...")
                # process_cert is where you check associated IPs, blacklist if too verbose,
                # then add it to the event or update it if it already exists
                # event = process_cert(mh, obj, event)

        # TODO FUTURE-PROOF
        # elif obj.name == "misphunter-dns":
        #     if obj.uuid not in mh.event_processed_object_uuids:
        #         process_dns(mh, obj, event)
        # elif obj.name == "misphunter-malware":
        #     if obj.uuid not in mh.event_processed_object_uuids:
        #         process_malware(mh, obj, event)
        
        else:
            mh.logger.info(f"Object type {obj.name} is unknown. This should not happen. Skipping/removing")

        mh.event_new_objects.remove(obj)
        if obj.uuid in mh.event_new_object_uuids:
            mh.event_new_object_uuids.remove(obj.uuid)
        if obj.uuid not in mh.event_processed_object_uuids:
            mh.logger.debug(f"This should not happen. I did not expect to be adding this UUID right now.")
            mh.event_processed_object_uuids.append(obj.uuid)
            
    if len(mh.event_new_objects) == 0:
        return event
    done = process_event_new_objects(mh, event)
    if done:
        mh.logger.info(f"Finished processing new objects!")
        return event

def process_host(mh, host_obj, event):
    mh.logger.info(f"Processing host object {host_obj.uuid}")
    # Enrich the host object by extracting IOCs, comparing changes, etc.
    host_obj = helper.enrich_host_obj(mh, host_obj)

    # host_obj.is_new if it's newly built or if it was cloned from another event.
    # If this host object is new to this event, add it to the event and get the latest version of the event.
    if host_obj.is_new:
        added_obj = event.add_object(host_obj, pythonify=True)
        updated_event = misphandler.update_event(mh, event)
        if not updated_event:
            mh.logger.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object. Using "
                "pre-existing event going forward.")
        else:
            event = updated_event

        mh.logger.info(f"Processed new host_obj {added_obj.uuid}. Adding to mh.event_processed_object_uuids!")
        mh.event_processed_object_uuids.append(added_obj.uuid)


    # If this host object is not new to this event update the object, then re-pull the whole event for good measure.
    else:
        updated_object = misphandler.update_existing_object(mh, host_obj)
        if not updated_object:
            mh.logger.error(f"Error updating existing object {host_obj.uuid} in event {event.id}. Returned False "
                "instead of MISPEvent Object.")
        else:
            mh.logger.info(f"Processed existing host_obj {updated_object.uuid}. Adding to mh.event_processed_object_uuids!")
            mh.event_processed_object_uuids.append(updated_object.uuid)            

            host_obj = updated_object
            updated_event = misphandler.get_event(mh, host_obj.event_id)
            if not updated_event:
                mh.logger.error(f"SIMPLY GETTING event {host_obj.event_id} FAILED. Returned False instead "
                    "of MISPEvent Object. Using pre-existing event going forward.")
            else:
                # Update the global "existing lists" every time there's a successful MISPObject-only update
                event = updated_event
                mh.event_hosts = misphandler.get_event_objects(mh, event, 'misphunter-host')
                mh.event_seeds = misphandler.get_event_objects(mh, event, 'misphunter-seed')
                mh.event_certs = misphandler.get_event_objects(mh, event, 'misphunter-cert')
                mh.event_dns = misphandler.get_event_objects(mh, event, 'misphunter-dns')
                mh.event_malware = misphandler.get_event_objects(mh, event, 'misphunter-malware')

    # Collect pivot objects and send to mh.event_new_objects
    if mh.cert_pivoting:
        event = collect_pivot_objects(mh, host_obj, event, pivot="extracted-certificate")
    
    return event

def collect_pivot_objects(mh, obj, event, pivot=""):
    mh.logger.info(f"Collecting pivot objects from {obj.name} object for pivot type {pivot}")
    min_epoch = int(time()) - (mh.update_threshold * 60 * 60)
    attrs = misphandler.get_all_attrs_by_rel(obj, pivot)
    for attr in attrs:
        if int(attr.last_seen.timestamp()) > min_epoch:
            attr.value
            if pivot == "extracted-certificate":
                # if we are pivoting on an extracted-certificatre, this will generate
                # a misphunter-cert object
                mh.logger.debug(f"Collecting pivot objects for {pivot}...")
                pivot_obj = helper.get_cert_obj(mh, attr.value, obj, event)
            elif pivot == "cert-ip":
                # if we are pivoting on a cert-ip, this will generate a misphunter-host object
                mh.logger.debug(f"Collecting pivot objects for {pivot}...")
                pivot_obj = misphandler.get_host_obj(mh, event, attr.value)
            else:
                mh.logger.warning(f"Received pivot {pivot} but I don't know how to process that!")
                pivot_obj = False

            if not pivot_obj:
                mh.logger.info(f"Unable to find or build object for {attr.value}. Skipping!")
                continue

            blacklisted = misphandler.get_attr_val_by_rel(pivot_obj, 'blacklisted')
            if int(blacklisted) == 1:
                mh.logger.info(f"Extracted {pivot_obj.name} object {pivot_obj.uuid} is blacklisted. Skipping!")
                continue

            if pivot_obj.uuid not in mh.event_processed_object_uuids:
                
                if pivot_obj.uuid not in mh.event_new_object_uuids:
                    mh.logger.info(f"Adding {pivot_obj.name} object {pivot_obj.uuid} to mh.event_new_objects for further processing!")
                    mh.event_new_objects.append(pivot_obj)
                    mh.event_new_object_uuids.append(pivot_obj.uuid)
            else:
                mh.logger.debug(f"{pivot_obj.name} object {pivot_obj.uuid} has already been processed...")
                    
            

def process_hosts_kinda_old(mh, ips, event):

    mh.logger.info(f"Processing {len(ips)} discovered hosts: {ips}.")
    blocks = misphandler.get_local_blocks(mh, event)
    mh.logger.debug(f"All blocks: {blocks}")

    # Loop through each IP discovered
    for ip in ips:
        # Check IP against local and gloabl blocks
        if helper.check_block(mh, ip, blocks):
            continue
        mh.logger.info(f"Processing IP {ip}")
        # Get existing misphunter-host object or create new one
        host_obj = misphandler.get_host_obj(mh, ip, event)
        # NOTE: host_obj returns .is_new=True if it's a newly built host object or a clone
        #   returns .is_new=False if it already existed in this event
        if not host_obj:
            mh.logger.error(f"After processing IP {ip} with get_host_obj() something still managed to go wrong. "
                "Skipping this host.")
            continue

        # Enrich the host object by extracting IOCs, comparing changes, etc.
        host_obj = helper.enrich_host_obj(mh, host_obj)

        # host_obj.is_new if it's newly built or if it was cloned from another event.
        # If this host object is new to this event, add it to the event and get the latest version of the event.
        if host_obj.is_new:
            added_obj = event.add_object(host_obj, pythonify=True)
            updated_event = misphandler.update_event(mh, event)
            if not updated_event:
                mh.logger.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object. Using "
                    "pre-existing event going forward.")
            else:
                event = updated_event

            if added_obj.uuid not in mh.event_new_object_uuids:
                mh.logger.info(f"Created new host_obj {added_obj.uuid}. Adding to mh.event_new_objects!")
                mh.event_new_object_uuids.append(added_obj.uuid)
                mh.event_new_objects.append(added_obj)
            else:
                mh.logger.warning(f"Created new host_obj {added_obj.uuid} but it was already in mh.event_new_object_uuids."
                    "THIS SHOULD NOT HAPPEN!")

        # If this host object is not new to this event update the object, then re-pull the whole event for good measure.
        else:
            updated_object = misphandler.update_existing_object(mh, host_obj)
            if not updated_object:
                mh.logger.error(f"Error updating existing object {host_obj.uuid} in event {event.id}. Returned False "
                    "instead of MISPEvent Object.")
            else:
                
                if updated_object.uuid not in mh.event_new_object_uuids:
                    mh.logger.info(f"Updated host_obj {updated_object.uuid}. Adding to mh.event_new_objects!")
                    mh.event_new_object_uuids.append(updated_object.uuid)
                    mh.event_new_objects.append(updated_object)
                else:
                    mh.logger.warning(f"Created new host_obj {updated_object.uuid} but it was already in mh.event_new_object_uuids."
                        "THIS SHOULD NOT HAPPEN!")

                host_obj = updated_object
                updated_event = misphandler.get_event(mh, host_obj.event_id)
                if not updated_event:
                    mh.logger.error(f"SIMPLY GETTING event {host_obj.event_id} FAILED. Returned False instead "
                        "of MISPEvent Object. Using pre-existing event going forward.")
                else:
                    # Update the global "existing lists" every time there's a successful MISPObject-only update
                    event = updated_event
                    mh.event_hosts = misphandler.get_event_objects(mh, event, 'misphunter-host')
                    mh.event_seeds = misphandler.get_event_objects(mh, event, 'misphunter-seed')
                    mh.event_certs = misphandler.get_event_objects(mh, event, 'misphunter-cert')
                    mh.event_dns = misphandler.get_event_objects(mh, event, 'misphunter-dns')
                    mh.event_malware = misphandler.get_event_objects(mh, event, 'misphunter-malware')

    # Cert pivoting used to take place here - moving it to a simpler area
    return event


def process_seeds_old(mh, seeds, event):
    for seed in seeds:
        mh.run_search = False
        # Check timer for each seed to make sure we're not running prematurely
        # Also sets self.run_search to True if it's time to run the seed search again
        seed = misphandler.check_timer(mh, seed)
        if mh.run_search:
            seed_service = misphandler.get_attr_val_by_rel(seed, 'service')
            if not seed_service:
                mh.logger.error(f"No service found associated with seed object {seed.uuid}. Skipping seed!")
                continue
            seed_search = misphandler.get_attr_val_by_rel(seed, 'search-string')
            if not seed_search:
                mh.logger.error(f"No search string found associated with seed object {seed.uuid}. Skipping seed!")
                continue
            mh.logger.debug(f"Timer checks have passed. Processing seed for [{seed_service}] - {seed_search}...")
            # mh.logger.debug(f"Checking if {seed_service} is in mh.host_seed_services - {mh.host_seed_services}")
            if seed_service in mh.host_seed_services:
                ips = helper.run_host_seed(mh, seed_search, seed_service)
                if len(ips) <= 0:
                    mh.logger.error(f"No IPs were found running {seed_service} search {seed_search}.Skipping seed!")
                    continue
                else:
                    new_ip_found = False
                    # Add all found IPs to seed first
                    mh.logger.debug(f"Found {len(ips)} IPs while searching {seed_service} with seed {seed.uuid}!")
                    seed_found_ips = []
                    seed_ip_attrs = misphandler.get_all_attrs_by_rel(seed, 'found-host')
                    for attr in seed_ip_attrs:
                        if attr.value not in seed_found_ips:
                            seed_found_ips.append(attr.value)
                    for ip in ips:
                        if ip not in seed_found_ips:
                            seed_found_ips.append(ip)
                            mh.logger.info(f"Adding found IP {ip} to seed object {seed.uuid}.")
                            new_ip_found = seed.add_attribute('found-host', ip, type='ip-dst', disable_correlation=False, to_ids=False, pythonify=True)
                            misphandler.update_timestamps(mh, new_ip_found)
                        else:
                            ip_attrs = misphandler.get_all_attrs_by_rel(seed, 'found-host')
                            for attr in ip_attrs:
                                if attr.value == ip:
                                    misphandler.update_timestamps(mh, attr)

                    if new_ip_found:
                        updated_seed = misphandler.update_existing_object(mh, seed)
                        if not updated_seed:
                            mh.logger.error(f"Error attempting to update seed object {seed.uuid} with new found-ips {ips}.")
                        else:
                            seed = updated_seed
                            updated_event = misphandler.get_event(mh, seed.event_id)
                            if updated_event:
                                mh.logger.debug(f"Successfully grabbed event {seed.event_id}.")
                                event = updated_event
                            else:
                                mh.logger.error(f"Attempting to get event after adding found-hosts to seed {seed.uuid} failed.")

                    updated_event = process_hosts(mh, event, seed, ips)
                    if updated_event:
                        event = updated_event
                    else:
                        mh.logger.error(f"running process_hosts with seed {seed.uuid} and ips {ips} FAILED. Event NOT updated..")


            # TODO - FUTURE - add different types of seed results to be processed
            # elif seed_service in mh.dns_seed_services:
            #     domains = helper.run_dns_seed(mh, seed_search, seed_service)

    # Update event before exiting the routine
    updated_event = misphandler.update_event(mh, event)
    if not updated_event:
        mh.logger.error(f"Something went wronng trying to update the final MISPEvent of the process_seeds() routine!")
        mh.logger.debug(f"returning untouched event that was sent to the process_seeds routine. FIGURE IT OUT!")
    else:
        event = updated_event
    mh.logger.debug(f"Finished processing {len(seeds)} seeds!")
    return event

def process_hosts_old(mh, event, seed, ips):

    # TODO - NOTE - BY PASSING SEED THIS WAY I BELIEVE I'M LIMITING IT TO ONLY 
    # USING THE SERVICE THAT THE ORIGINAL SEED BELONGED TO
    # (e.g. censys seed found host, so only got censys data, not shodan)
    # IT MIGHT NOT MATTER THOUGH AS LONG AS I'M PIVOTING OFF OTHER ENABLED OBJECTS
    # THAT DIDN'T COME BACK FROM THE SEED SEARCH
    # TODO - In second round of searches (objects that weren't touched in first seed round)
    #   check for any host objects that don't have at least one JSON blob for each service

    updated_event = False
    updated_host_obj = False
    new_host_obj = True
    # Get blocks local to this event
    blocks = misphandler.get_local_blocks(mh, event)
    mh.logger.debug(f"All blocks: {blocks}")
    
    # Loop through each IP found by the Seed Object's search string
    mh.logger.info(f"Processing {len(ips)} discovered hosts: {ips}")
    for ip in ips:
        # Check IP against local and global blocks
        if helper.check_block(mh, ip, blocks):
            continue
        mh.logger.info(f"Processing IP {ip}")
        # get existing misphunter-host object or create new one
        host_obj = misphandler.get_host_obj(mh, event, seed, ip)
        # host_obj returns .is_new=True if it's a newly built host object, or if it's a new clone
        # of an existing object.
        if not host_obj:
            mh.logger.error(f"After processing IP {ip} with get_host_obj() something still managed to go wrong. Skipping this host.")
            continue

        # Enrich the Host Object by extracting IOCs, comparing changes, etc.
        host_obj = helper.enrich_host_obj(mh, event, seed, host_obj)

        # Check if this object existed when we first started processing this event
        for existing_obj in mh.event_hosts:
            if host_obj.uuid == existing_obj.uuid:
                mh.logger.info(f"host object {host_obj.uuid} found already existing in this event.")
                new_host_obj = False

        # Check if host_obj is new (e.g. a cloned or newly-built object)
        if hasattr(host_obj, 'is_new'):
            if host_obj.is_new:
                mh.logger.info(f"host object {host_obj.uuid} is new (newly built or cloned from another event).")
                new_host_obj = True

        # If this host object is new to this event, add it to the event and get the latest version of the event.
        if new_host_obj:
            event.add_object(host_obj, pythonify=True)
            updated_event = misphandler.update_event(mh, event)
            if not updated_event:
                mh.logger.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object. Using pre-existing event going forward.")
            else:
                event = updated_event

        # If this host object is not new to this event update the object, then re-pull the whole event for good measure.
        else:
            updated_object = misphandler.update_existing_object(mh, host_obj)
            if not updated_object:
                mh.logger.error(f"Error updating existing object {host_obj.uuid} in event {event.id}. Returned False instead of MISPEvent Object.")
            else:
                host_obj = updated_object
                updated_event = misphandler.get_event(mh, updated_object.event_id)
                if not updated_event:
                    mh.logger.error(f"SIMPLY GETTING event {event.id} FAILED. Returned False instead of MISPEvent Object. Using pre-existing event going forward.")
                else:
                    # Update the global "existing lists" every time there's a successful MISPObject-only update
                    misphandler.get_event_seeds(mh, event)
                    misphandler.get_event_hosts(mh, event)
                    misphandler.get_event_certs(mh, event)
                    misphandler.get_event_dns(mh, event)
                    misphandler.get_event_malware(mh, event)
                    event = updated_event

        # Assuming cert_pivoting is enabled, attempt to find more hosts sharing the same certificate as this IP.
        if mh.cert_pivoting:
            updated_event = cert_pivot(mh, host_obj, event, seed)
            if not updated_event:
                mh.logger.error(f"Something bad happened while trying to run cert_pivot(). Event was not updated.")
            else:
                event = updated_event

    return event
'''


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

    new_tags = []

    new_time = int(time()) - (int(mh.new_discovery_threshold) * 60 * 60)

    for obj in event.Object:
        for attr in obj.Attribute:
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
                    misphandler.tag(mh, attr, tag)
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
                        misphandler.untag(mh, attr, tag)
                        # Track stats
                        helper.track_stats_tags_removed(mh, tag, attr)

                
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
    rel_index = helper.organize_event_objects(mh, event)
    # Relate certs to IPs they were found on
    rel_index = helper.build_cert_host_rels(mh, event, rel_index)
    # Relate seeds to hosts those seeds discovered
    rel_index = helper.build_seed_host_rels(mh, event, rel_index)
    # Update the event to finalize the relationships
    event = misphandler.update_event(mh, event)
    return event

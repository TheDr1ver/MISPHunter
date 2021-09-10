from copy import deepcopy
import json
import logging, logging.handlers
import sys
import uuid

from datetime import datetime
from io import BytesIO
from pprint import pformat
from time import time, sleep

from pymisp import MISPObject

##################################
#### 2-Stage Approach Functions
###################################

def create_obj_skeleton(mh, object_name="", value="", rel=""):
    
    mh.logger.info(f"Building {object_name} skeleton...")
    template = mh.misp.get_raw_object_template(object_name)
    obj = MISPObject(object_name, misp_objects_template_custom=template)
    obj.is_new = True
    obj.add_attribute(rel, value, type=mh.rel_type_mapping[rel], disable_correlation=False, to_ids=False, pythonify=True)
    obj.add_attribute('blacklisted', '0', type="boolean", disable_correlation=True, to_ids=False, pythonify=True)

    # Update timestamps
    for attr in obj.Attribute:
        update_timestamps(mh, attr)

    return obj

###################################

def add_ips_to_cert_obj(mh, cert_data, ips):
    existing_ips = []
    ip_attrs = cert_data.get_attributes_by_relation('cert-ip')
    # Check the IPs already in this cert_data object
    for ip in ip_attrs:
        if ip.value not in existing_ips:
            existing_ips.append(ip.value)
            if ip.value in ips:
                update_timestamps(mh, ip)
    # If any of the IPs we found weren't already in this misphunter-cert object
    # add them, with a comment of where we found them.
    added_ips = []
    for hunt_type, ips in ips.items():
        for ip in ips:
            if ip not in existing_ips:
                if ip not in added_ips:
                    added_ips.append(ip)
                    comment=f"{ip} discovered via {hunt_type} search for associated hosts."
                    attr = cert_data.add_attribute('cert-ip', ip, type='ip-dst', comment=comment, disable_correlation=False, to_ids=False, pythonify=True)
                    update_timestamps(mh, attr)
    return cert_data

def add_json_attr(mh, checksum, raw_sorted_json_text, host_obj, json_type, comment=""):

    json_filename = str(checksum)+".json"
    mh.logger.info(f"Saving raw JSON blob {json_filename} to host_obj {host_obj.uuid}...")
    pseudofile = BytesIO(raw_sorted_json_text.encode('utf-8'))
    new_attr = host_obj.add_attribute(json_type, value=json_filename, comment=comment, type='attachment', to_ids=False, data=pseudofile, distribution=5)
    update_timestamps(mh, new_attr)
    mh.logger.debug(f"Object updated. Returning {host_obj}")
    
    return host_obj

def blacklist_cert(mh, cert_data, comment):
    
    cert_hash = get_attr_val_by_rel(cert_data, 'cert-sha256')
    cert_hash_attr = get_attr_obj_by_rel(cert_data, 'cert-sha256')
    ips = get_all_attrs_by_rel(cert_data, 'cert-ip')
    cert_hash_attr.comment = comment

    # mh.logger.warning(f"Search returned {len(ips)} IPs. Threshold set to > 1 and < {mh.cert_pivot_threshold}.")
    mh.logger.warning(f"Disabling misphunter-cert object {cert_hash} - [{cert_data.uuid}] "
        f"for future pivoting.")

    blacklisted = get_attr_obj_by_rel(cert_data, 'blacklisted')

    if int(blacklisted.value) == 0:

        blacklisted.value = 1
        
        # if this object already exists in the event, update it
        cert_obj_exists = mh.misp.get_object(cert_data.uuid, pythonify=True)
        if not isinstance(cert_obj_exists, dict):
            cert_data = update_existing_object(mh, cert_data)

        if 'auto_blacklists_added' not in mh.run_stats:
            mh.run_stats['auto_blacklists_added'] = {}
        if cert_data.event_id not in mh.run_stats['auto_blacklists_added']:
            mh.run_stats['auto_blacklists_added'][cert_data.event_id] = {}
        if 'misphunter-certs' not in mh.run_stats['auto_blacklists_added'][cert_data.event_id]:
            mh.run_stats['auto_blacklists_added'][cert_data.event_id]['misphunter-certs'] = []
        mh.run_stats['auto_blacklists_added'][cert_data.event_id]['misphunter-certs'].append(cert_hash)
        mh.run_stats['auto_blacklists_added']['total']+=1
        
    return cert_data
    
def blacklist_check_cert(mh, cert):
    # mh.logger.debug(f"Checking misphunter-cert object {cert.uuid} to determine if it should be blacklisted.")
    cert_ips = cert.get_attributes_by_relation('cert-ip')
    sha256 = get_attr_val_by_rel(cert, 'cert-sha256')
    if len(cert_ips) <= 1 or len(cert_ips) >= mh.cert_pivot_threshold:
        comment = f"Cert {sha256} - {cert.uuid} had {len(cert_ips)} IPs associated with it.\n" \
            f"\tPivot threshold currently set to {mh.cert_pivot_threshold}.\n"\
            f"\tBlacklisting cert from future pivots!"
        mh.logger.info(comment)
        cert = blacklist_cert(mh, cert, comment)
            
    else:
        mh.logger.debug(f"Cert {sha256} - {cert.uuid} had {len(cert_ips)} IPs associated with it. Leaving blacklist val alone!")
    return cert

def build_misphunter_cert(mh, cert, parent_obj, event, raw_data):
    
    parsed_data = raw_data['parsed']
    mh.logger.info(f"Building a new misphunter-cert object for {parsed_data['fingerprint_sha256']}!")

    cert_temp = mh.misp.get_raw_object_template('misphunter-cert')
    cert_obj = MISPObject('misphunter-cert', misp_objects_template_custom=cert_temp)
    cert_obj.is_new = True
    cert_obj.add_attribute('cert-sha256', parsed_data['fingerprint_sha256'], type="x509-fingerprint-sha256", disable_correlation=True, to_ids=False, pythonify=True)
    cert_obj.add_attribute('cert-sha1', parsed_data['fingerprint_sha1'], type="x509-fingerprint-sha1", disable_correlation=True, to_ids=False, pythonify=True)
    cert_obj.add_attribute('cert-md5', parsed_data['fingerprint_md5'], type="x509-fingerprint-md5", disable_correlation=True, to_ids=False, pythonify=True)
    cert_obj.add_attribute('cert-issuer-dn', parsed_data['issuer_dn'], type="text", disable_correlation=True, to_ids=False, pythonify=True)
    cert_obj.add_attribute('cert-subject-dn', parsed_data['subject_dn'], type="text", disable_correlation=True, to_ids=False, pythonify=True)
    cert_obj.add_attribute('blacklisted', '0', type="boolean", disable_correlation=True, to_ids=False, pythonify=True)
    attrs = parent_obj.get_attributes_by_relation('host-ip')
    if len(attrs)>0:
        ip = attrs[0].value
        cert_obj.add_attribute('cert-ip', ip, type="ip-dst", disable_correlation=False, to_ids=False, pythonify=True)

    # Add the raw results as a JSON file
    raw_data_text = json.dumps(raw_data)
    json_filename = f"{parsed_data['fingerprint_sha256']}.json"
    pseudofile = BytesIO(raw_data_text.encode('utf-8'))
    cert_obj.add_attribute('json', value=json_filename, data=pseudofile, type='attachment', disable_correlation=True, to_ids=False, pythonify=True)

    # Add any names as domains
    if 'names' in parsed_data:
        for name in parsed_data['names']:
            domain = name.lstrip("*.")
            cert_obj.add_attribute('cert-domain', domain, type="domain", disable_correlation=False, to_ids=False, pythonify=True)

    # Add relationship
    # comment=f"Certificate was seen on {ip}"
    # cert_obj.add_reference(parent_obj.uuid, "derived-from", comment=comment)

    sha256 = parsed_data['fingerprint_sha256']
    if 'certs_added' not in mh.run_stats:
        mh.run_stats['certs_added'] = {str(event.id): [sha256]}
    elif str(event.id) not in mh.run_stats['certs_added']:
        mh.run_stats['certs_added'][str(event.id)] = [sha256]
    else:
        mh.run_stats['certs_added'][str(event.id)].append(sha256)
    mh.run_stats['certs_added']['total']+=1

    for attr in cert_obj.Attribute:
        update_timestamps(mh, attr)
    
    return cert_obj

def build_new_host_obj(mh, event, ip):
    mh.logger.info(f"MISP Object for {ip} does not exist. Building a new one.")
    try:
        raw_template = mh.misp.get_raw_object_template('misphunter-host')
    except Exception as e:
        mh.logger.error(f"Could not get template for misphunter-host. Host {ip} WILL NOT BE ADDED: {e}")
        return False
    host_obj = MISPObject('misphunter-host', misp_objects_template_custom=raw_template)
    host_obj.is_new = True
    host_obj.add_attribute('host-ip', value=str(ip), type='ip-dst', to_ids=False)
    host_obj.add_attribute('blacklisted', value=str(0), type='boolean', to_ids=False)
    # Update timestamps
    for attr in host_obj.Attribute:
        update_timestamps(mh, attr)
    
    if 'hosts_added' not in mh.run_stats:
        mh.run_stats['hosts_added'] = {str(event.id) : [ip]}
    elif str(event.id) not in mh.run_stats['hosts_added']:
        mh.run_stats['hosts_added'][str(event.id)] = [ip]
    else:
        mh.run_stats['hosts_added'][str(event.id)].append(ip)
    mh.run_stats['hosts_added']['total']+=1

    return host_obj

def check_all_certs(mh, cert, event):
    # Returns False if nothing found, otherwise returns the latest misphunter-cert MISPObject
    cert_data = False
    mh.logger.info(f"Saving API queries by checking if cert already exists in database...")

    try:
        all_cert_data = mh.misp.search(controller="objects", object_name="misphunter-cert", value=cert, pythonify=True)
    except Exception as e:
        mh.logger.error(f"FAILED attempt at searching for all existing certificates of value {cert}...")
        return False

    mh.logger.debug(f"Found {len(all_cert_data)} certs matching value {cert}.")

    event_cert_uuids = []
    for event_cert in mh.event_certs:
        if event_cert.uuid not in event_cert_uuids:
            event_cert_uuids.append(event_cert.uuid)

    for obj in all_cert_data:
        if obj.uuid in event_cert_uuids:
            mh.logger.info(f"Found a cert object that already lives in this exact event, so that's the one we'll use: {obj.uuid}")
            cert_data = obj
            cert_data.is_new = False
            cert_data.is_clone=False
            return cert_data

        if cert_data == False:
            mh.logger.debug(f"Found first cert object for {cert}: {obj.uuid}")
            cert_data = obj
        else:
            if int(obj.timestamp.timestamp()) > int(cert_data.timestamp.timestamp()):
                mh.logger.debug(f"Found newer cert object [{obj.uuid}] to replace existing cert object {cert_data.uuid}")
                cert_data = obj
        
    if cert_data:
        if str(cert_data.event_id)!=str(event.id):
            mh.logger.info(f"Found existing cert object {cert_data.uuid} from a different event. Cloning object for this event!")
            cert_data = clone_obj(mh, cert_data, event)
            cert_data.is_clone=True
    
    return cert_data

def check_tags(obj):
    tags = []
    if hasattr(obj, 'Tag'):
        for tag in obj.Tag:
            if tag.name not in tags:
                tags.append(tag.name)
    return tags

def check_json_freshness(mh, host_obj, service):
    mh.logger.info(f"First checking to see if we have an existing json blob new enough to avoid using an API query.")
    json_type = f"{service}-json"
    last_json = get_latest_attr_by_rel(host_obj, json_type)
    threshold_timestamp = int(time()) - (int(mh.update_threshold) * 60 * 60)
    if last_json:
        mh.logger.info(f"{last_json.value} found of type {json_type}. Checking to see if it's new enough...")
        if int(last_json.last_seen.timestamp()) >= int(threshold_timestamp):
            mh.logger.info(f"JSON timestamp of {int(last_json.last_seen.timestamp())} > {mh.update_threshold} hours ago ({int(threshold_timestamp)})."
                "new enough to reuse!")

            if not hasattr(host_obj, 'is_new'):
                host_obj.is_new = False

            if not host_obj.is_new:
                mh.logger.debug(f"attempting to read {last_json.value}...")
                if not last_json.data:
                    mh.logger.warning(f"Data missing from {last_json.value}... Trying some magic.")
                    last_json = mh.misp.get_attribute(last_json, pythonify=True)
                if not last_json.data:
                    mh.logger.warning(f"Still no go. RETURNING FALSE!")
                    return False
                else:
                    mh.logger.info(f"The magic appears to have worked!")
                bytes_obj = last_json.data.read()
                last_json.data.seek(0)
                json_str = bytes_obj.decode('utf-8').replace("'", '"')
                try:
                    raw = json.loads(json_str)
                except Exception as e:
                    mh.logger.error(f"Error attempting to load json: {e}")
                    mh.logger.error(f"Something went wrong attempting to read {last_json.value}. Skipping re-use and "
                        "just going to hit the API again.")
                    return False
                # set misphunter_processed to make sure we're not re-processing this JSON object
                raw['misphunter_processed'] = True
                return raw
            else:
                mh.logger.info(f"BUT WAIT - host_obj {host_obj.uuid} is_new! Better get a fresh JSON blob to be safe!")
                return False
        else:
            mh.logger.info(f"It had a timestamp of {int(last_json.last_seen.timestamp())} and we wanted it to be > "
                f"{mh.update_threshold} hrs ago ({int(threshold_timestamp)}). Getting fresh JSON blob for comparison.")
            return False
    else:
        return False

def check_timer(mh, seed):
    # Returns seed with updated last_run time (or updated object timestamp in ignoring timers in debugging mode)
    mh.logger.info(f"Checking event timer to see if seed {seed.uuid} is ready to update")
    update_seed_object = False
    run_search = False
    now = int(time())

    last_run = get_attr_val_by_rel(seed, 'last-run')

    # If no last_run time found, update event
    if last_run:
        mh.logger.info(f"seed last ran: {last_run}")
        last_run_time = int(last_run.timestamp())
    else:
        mh.logger.info(f"Search does not have a record of when it was last run. Setting last run timestamp to 0.")
        last_run_time = 0
        if not mh.ignore_timers:
            seed.add_attribute('last-run', now, type="datetime", disable_correlation=True, pythonify=True)
        else:
            mh.logger.info(f"ignore_timers flag is set, so not adding a last_run attribute to this event.")
        mh.logger.debug(f"Setting update_seed_object to True.")
        update_seed_object = True

    freq = get_attr_val_by_rel(seed, 'update-freq')
    mh.logger.info(f"Search frequency for seed {seed.uuid} set to run once every {freq} hours.")

    # If no frequency time found, update event
    if freq:
        freq_time = int(freq) * 60 * 60
    else:
        mh.logger.info(f"Search does not have a frequency set. Defaulting to 24 hours.")
        freq_time = 24 * 60 * 60
        # Ignore frequency attribute if running in debugger mode (avoids having to delete it every time)
        if not mh.ignore_timers:
            seed.add_attribute('update-freq', '24', type='text', disable_correlation=True, comment="Search is re-run every time this many hours have passed.", pythonify=True)
        else:
            mh.logger.info(f"ignore_timers flag is set, so not adding a frequency attribute to this event.")
        mh.logger.debug(f"Setting update_seed_object to True.")
        update_seed_object = True

    time_passed = now - int(last_run_time)
    # If no last_run_time set, this will always be true because time_passed/epoch is > whatever freq is set to.
    if time_passed >= freq_time:
        update_seed_object = True
        mh.logger.info(f"{str(time_passed/60/60)} hours have passed. Time to run the search again!")
        # Ignore last_run attribute if running in debugger mode (avoids having to delete it every time)
        if not mh.ignore_timers:
            # Update the last_run value to now            
            for attr in seed.Attribute:
                if attr.object_relation == "last-run":
                    dtnow = datetime.utcfromtimestamp(now)
                    attr.value=dtnow
        else:
            mh.logger.info(f"ignore_timers flag is set so not updating last_run attribute.")

        mh.logger.debug(f"Setting mh.run_search to True...")
        run_search = True

    if update_seed_object:
        mh.logger.info(f"Updating MISP event with new run time or frequency.")
        # Seting new timestamp during debugging because otherwise nothing in the event will have changed
        if mh.ignore_timers:
            # event.timestamp = now
            seed.timestamp = now
        # event = mh.misp.update_event(event, pythonify=True)
        try:
            seed = mh.misp.update_object(seed, pythonify=True)
        except Exception as e:
            mh.logger.error(f"Error attempting to update last-run timer for seed object {seed.uuid}: {e}")
            mh.logger.debug(f"Running the search even though somehow the seed is messed up.")
            mh.run_search = True
    else:
        hours_passed = time_passed/60/60
        mh.logger.info(f"{str(hours_passed)} hours have passed. Time limit has not been reached. No search will be run for seed {seed.uuid}.")
    
    if mh.ignore_timers:
        mh.logger.info(f"...GOTCHA!! ignore_timers was set to True so all of that meant NOTHING and we're gonna run it anyway!")
        run_search = True

    return run_search, seed

def clone_obj(mh, source_obj, event):
    if str(source_obj.event_id) == str(event.id):
        mh.logger.info(f"Object {source_obj.uuid} does not need to be cloned because it already exists in this event.")
        mh.logger.error(f"THIS IS LEGACY CODE")
        mh.logger.error(f"THIS SHOULD NOT HAPPEN")
        mh.logger.error(f"WE SHOULD HAVE ALREADY GRABBED THE OBJECT FROM THE EVENT BY NOW.")
        source_obj.is_new=False
        return source_obj
    else:
        mh.logger.info(f"Discovered object [{source_obj.uuid}] has a different "
            f"event_id ({source_obj.event_id}) than "f"the event we're "
            f"processing ({event.id}). Creating a new object")
    clone = deepcopy(source_obj)
    clone.uuid = str(uuid.uuid4())
    clone.event_id = event.id
    for attr in clone.Attribute:
        attr.uuid = str(uuid.uuid4())
        attr.event_id = event.id
    # Update timestamps for obj type index value
    if clone.name in mh.obj_index_mapping:
        obj_index = mh.obj_index_mapping[clone.name]
        attrs = clone.get_attributes_by_relation(obj_index)
        for attr in attrs:
            update_timestamps(mh, attr)
    clone.is_new=True

    if 'clones_added' not in mh.run_stats:
        mh.run_stats['clones_added'] = {str(event.id) : [clone.uuid]}
    elif str(event.id) not in mh.run_stats['clones_added']:
        mh.run_stats['clones_added'][str(event.id)] = [clone.uuid]
    else:
        mh.run_stats['clones_added'][str(event.id)].append(clone.uuid)
    mh.run_stats['clones_added']['total']+=1

    return clone

def get_all_attrs_by_rel(obj, rel):
    # mh.logger.debug(f"Getting ALL Attribute OBJECTs from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        return attrs
    else:
        return []

def get_attr_val_by_rel(obj, rel):
    # mh.logger.debug(f"Getting the VALUE of the FIRST attribute from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        attr_val = attrs[0].value
        # mh.logger.debug(f"attribute value {attr_val} found in object {obj.uuid} by relationship {rel}.")
        return attr_val
    else:
        return False

def get_attr_obj_by_rel(obj, rel):
    # mh.logger.debug(f"Getting the OBJECT of the FIRST attribute from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        attr = attrs[0]
        return attr
    else:
        return False

def get_event(mh, event_id):
    mh.logger.debug(f"Getting full MISPEvent Object for event {event_id}.")
    try: 
        event = mh.misp.get_event(event_id, pythonify=True)
    except Exception as e:
        mh.logger.error(f"Something went wrong trying to get misp event {event_id}: {e}")
        return False
    mh.event_hosts = get_event_objects(mh, event, 'misphunter-host')
    mh.event_seeds = get_event_objects(mh, event, 'misphunter-seed')
    mh.event_certs = get_event_objects(mh, event, 'misphunter-cert')
    mh.event_dns = get_event_objects(mh, event, 'misphunter-dns')
    mh.event_malware = get_event_objects(mh, event, 'misphunter-malware')
    return event

def get_all_event_seeds(mh):
    mh.logger.info(f"Getting all events and their associated misphunter-seeds.")
    all_event_seeds = {}
    try:
        seeds = mh.misp.search(controller="objects", object_name="misphunter-seed", pythonify=True)
    except Exception as e:
        mh.logger.error(f"Something went wrong trying to get misphunter-seed objects from all events: {e}")
        return False

    for seed in seeds:
        enabled = get_attr_val_by_rel(seed, 'enabled')
        if enabled=="0":
            ### TODO REMOVE ME - DEBUGGING
            # if mh.debugging:
            #     if str(seed.event_id) != '3978':
            #         continue
            # else:
            #     continue
            continue
        if seed.event_id not in all_event_seeds:
            all_event_seeds[str(seed.event_id)] = []
        if seed not in all_event_seeds[str(seed.event_id)]:
            
                all_event_seeds[str(seed.event_id)].append(seed)
    mh.logger.info(f"Found {len(all_event_seeds)} events with {len(seeds)} misphunter-seeds")
    mh.logger.debug(f"{all_event_seeds.keys()}")
    return all_event_seeds

def get_event_objects(mh, event, name):
    event_objects = []
    try:
        event_objects = event.get_objects_by_name(name)
    except Exception as e:
        mh.logger.error(f"Something went wrong trying to get {name} objects from event {event.id}: {e}")
    mh.logger.debug(f"Found {len(event_objects)} existing {name} objects in event {event.id}!")
    return event_objects

def get_global_blocks(mh):
    mh.logger.info(f"Searching MISP for globally blocked IPs")
    global_blocks=[]
    block_objects = mh.misp.search(controller="objects", object_name="misphunter-host-blacklist", pythonify=True)
    for bo in block_objects:
        bo_global_blocks = bo.get_attributes_by_relation('global-block')
        for bogb in bo_global_blocks:
            if bogb.value not in global_blocks:
                global_blocks.append(bogb.value)
    
    mh.logger.info(f"Found {len(global_blocks)} global blocks: {global_blocks}")
    return global_blocks

def get_host_obj(mh, ip, event):
    # First, check if this IP shows up in any misphunter-host objects already living in this event.
    for host_obj in mh.event_hosts:
        host_ip = get_attr_val_by_rel(host_obj, 'host-ip')
        if host_ip == ip:
            mh.logger.info(f"Found existing object already living in this event with host-ip {ip}: {host_obj.uuid}. Updating timestamp and returning that.")
            ip_attr = get_attr_obj_by_rel(host_obj, 'host-ip')
            update_timestamps(mh, ip_attr)
            host_obj.is_new=False
            return host_obj

    # Then, check if this IP shows up in any recently-updated misphunter-host objects living on the server.
    mh.logger.info(f"No existing object found in event {event.id} for IP {ip}. Searching the rest of the instance...")
    existing_obj = search_recent_updated_objects(mh, event, object_name="misphunter-host", value=ip, 
        timeframe=mh.update_threshold)
    if existing_obj:
        return existing_obj
    
    mh.logger.info(f"No existing object found server-wide. Building new host_obj.")
    host_obj = build_new_host_obj(mh, event, ip)
                
    return host_obj

def get_latest_attr_by_rel(obj, rel):
    latest_attr = False
    all_attrs = get_all_attrs_by_rel(obj, rel)
    for attr in all_attrs:
        if not latest_attr:
            latest_attr = attr
        else:
            last_seen = int(latest_attr.last_seen.timestamp())
            new_last_seen = int(attr.last_seen.timestamp())
            if new_last_seen > last_seen:
                latest_attr = attr
    return latest_attr

def get_local_blocks(mh, event):
    global_blocks = mh.global_blocks
    
    mh.logger.info(f"Getting local block list for {event.info}")
    
    local_blocks = global_blocks.copy()
    # search for IPs in local misphunter-host-blacklist objects
    for obj in event.Object:
        # Check any blacklist objects
        if obj.name == 'misphunter-host-blacklist':
            for attr in obj.Attribute:
                if not hasattr(attr, 'object_relation'):
                        continue
                if attr.object_relation == 'local-block':
                    if attr.value not in local_blocks:
                        local_blocks.append(attr.value)
        # Check if this specific host object is blacklisted
        if obj.name == "misphunter-host":
            attrs = obj.get_attributes_by_relation("blacklisted")
            if len(attrs) > 0:
                blacklisted = int(attrs[0].value)
            else:
                continue
            if blacklisted:
                hosts = obj.get_attributes_by_relation("host-ip")
                if len(hosts) > 0:
                    host = hosts[0].value
                    if host not in local_blocks:
                        local_blocks.append(host)

    return local_blocks

def parse_cert_data(mh, cert, raw):
    parsed_data = raw['parsed']
    mh.logger.info(f"Parsing data for {cert.name} [{cert.uuid}] - "
        f"{parsed_data['fingerprint_sha256']}!")

    cert.add_attribute('cert-sha1', parsed_data['fingerprint_sha1'], 
        type="x509-fingerprint-sha1", disable_correlation=True, to_ids=False, 
        pythonify=True)
    cert.add_attribute('cert-md5', parsed_data['fingerprint_md5'], 
        type="x509-fingerprint-md5", disable_correlation=True, to_ids=False, 
        pythonify=True)
    cert.add_attribute('cert-issuer-dn', parsed_data['issuer_dn'], 
        type="text", disable_correlation=True, to_ids=False, pythonify=True)
    cert.add_attribute('cert-subject-dn', parsed_data['subject_dn'], 
        type="text", disable_correlation=True, to_ids=False, pythonify=True)
    cert.add_attribute('blacklisted', '0', type="boolean", 
        disable_correlation=True, to_ids=False, pythonify=True)

    # Flag it as new so we know to populate related IPs
    cert.is_new = True

    # Add the raw results as a JSON file
    raw_data_text = json.dumps(raw)
    json_filename = f"{parsed_data['fingerprint_sha256']}.json"
    pseudofile = BytesIO(raw_data_text.encode('utf-8'))
    cert.add_attribute('json', value=json_filename, data=pseudofile, 
        type='attachment', disable_correlation=True, to_ids=False, 
        pythonify=True)

    # Add any names as domains
    if 'names' in parsed_data:
        for name in parsed_data['names']:
            domain = name.lstrip("*.")
            cert.add_attribute('cert-domain', domain, type="domain", 
                disable_correlation=False, to_ids=False, pythonify=True)

    # Process runtime stats
    sha256 = parsed_data['fingerprint_sha256']
    if 'certs_added' not in mh.run_stats:
        mh.run_stats['certs_added'] = {str(cert.event_id): [sha256]}
    elif str(cert.event_id) not in mh.run_stats['certs_added']:
        mh.run_stats['certs_added'][str(cert.event_id)] = [sha256]
    else:
        mh.run_stats['certs_added'][str(cert.event_id)].append(sha256)
    mh.run_stats['certs_added']['total']+=1

    for attr in cert.Attribute:
        update_timestamps(mh, attr)

    return cert

def search_recent_updated_objects(mh, event, object_name="", value="", rel="", timeframe=0):
    # This is called by the *_search_ip section of various plugins.
    # It is also called by get_host_obj
    #   It returns False if no object was discovered that was updated 
    #   in the last {timeframe} hours. Otherwise it
    #   returns MISPObject, which skips all the enrichment processes it
    #   would otherwise go through.
    newest_obj = False

    min_epoch = int(time()) - (timeframe * 60 * 60)
    # if timeframe set to 0, search all time (used for things like certs that shouldn't change)
    if timeframe == 0:
        min_epoch = 0

    try:
        misphunter_objs = mh.misp.search(controller="objects", object_name=object_name,
            value=value, timestamp=min_epoch, with_attachments=True, pythonify=True)
        mh.logger.info(f"Found {len(misphunter_objs)} results!")
    except Exception as e:
        mh.logger.error(f"Something went wrong trying to get {object_name} objects server-wide: {e}")
        return False

    for obj in misphunter_objs:
        attr_val = get_attr_val_by_rel(obj, rel)
        attr_obj = get_attr_obj_by_rel(obj, rel)
        if not attr_obj:
            mh.logger.error(f"Something went wrong. Apparently {object_name} object {obj.uuid} doesn't have a {rel} "
                f"associated with it. This should never happen. Dumping attributes and skipping for now.")
            for a in obj.Attribute:
                mh.logger.error(f"\n{pformat(a.to_dict())}")
                continue

        if not hasattr(attr_obj, 'last_seen'):
            mh.logger.error(f"{object_name} {rel} attribute doesn't have a last_seen timestamp. This is unusual. "
                "Adding one now.")
            attr_obj = update_timestamps(mh, attr_obj)
            attr_obj.last_seen = datetime.fromtimestamp(attr_obj.last_seen)

        obj_last_seen = int(attr_obj.last_seen.timestamp())
        if obj_last_seen < min_epoch:
            mh.logger.info(f"Skipping {obj.uuid} because the {rel} was last seen too long ago.")
            mh.logger.debug(f"Last_seen was {obj_last_seen} and we need it to be greater than {min_epoch} to "
                f"use it.")
            continue

        mh.logger.info(f"Looks like we're good to go with {obj.uuid}")
        mh.logger.debug(f"Last_seen was {obj_last_seen} and we need it to be less than {min_epoch} to "
            f"skip using it again")

        if attr_val == value:
            if not newest_obj:
                newest_obj = obj
                newest_attr = get_attr_obj_by_rel(newest_obj, rel)
                newest_obj_last_seen = int(newest_attr.last_seen.timestamp())
                continue
            if obj_last_seen >= newest_obj_last_seen:
                newest_obj = obj
                newest_attr = get_attr_obj_by_rel(newest_obj, rel)
                newest_obj_last_seen = int(newest_attr.last_seen.timestamp())

    if newest_obj:
        # Check if this object belongs to the event we're processing, otherwise clone it.
        if str(newest_obj.event_id) != str(event.id):
            mh.logger.info(f"Most-recently updated object is from a different event - [{newest_obj.event_id} vs {event.id}]")
            mh.logger.info(f"Cloning latest version of object {newest_obj.uuid} for adding to into event {event.id}")
            newest_obj = clone_obj(mh, newest_obj, event)
            attr_obj = get_attr_obj_by_rel(newest_obj, rel)
            # Fixing first_seen because it's the first time it was seen in this event, 
            # but not the first time in the whole instance because it was cloned.
            epoch = int(time())
            attr_obj.first_seen = epoch-2
        else:
            # A check should be done before search_recent_updated_objects() is ever called
            # to make sure that an appropriate object doesn't already exist in the event we're
            # currently processing. If we get here, it means that check was never run.
            mh.logger.debug(f"#### THIS SHOULD HAVE ALREADY BEEN CHECKED - "
                "YOU SHOULD NOT GET HERE - INVESTIGATE! ####")
            newest_obj.is_new=False

    return newest_obj

def tag(mh, obj, tag):
    mh.logger.debug(f"Tagging {type(obj)} {obj.uuid} as {tag}")
    try:
        mh.misp.tag(obj, tag)
    except Exception as e:
        mh.logger.error(f"Error tagging {type(obj)} {obj.uuid} -  {e}")

def untag(mh, obj, tag):
    mh.logger.debug(f"Removing tag {tag} from {type(obj)} {obj.uuid}...")
    try:
        mh.misp.untag(obj, tag)
    except Exception as e:
        mh.logger.error(f"Error UN-tagging {type(obj)} {obj.uuid} -  {e}")

def update_timestamps(mh, attr):
    mh.logger.debug(f"Updating timestamps for attribute {attr.value}.")
    epoch = int(time())
    if not hasattr(attr, 'timestamp'):
        attr.timestamp = epoch
        # mh.logger.debug(f"Updated {attr.value} timestamp to {epoch}")
    if not hasattr(attr, 'first_seen'):
        attr.first_seen = attr.timestamp
        # mh.logger.debug(f"Set {attr.value} first_seen to {attr.timestamp}")
    if not hasattr(attr, 'last_seen'):
        attr.last_seen = epoch
        # mh.logger.debug(f"Set {attr.value} last_seen to {epoch}")
    if epoch > int(attr.last_seen.timestamp()):
        attr.last_seen = epoch 
        # mh.logger.debug(f"Updated {attr.value} last_seen to {epoch}")
    return attr

def update_event(mh, event):
    updated_event = False
    # future = int(event.timestamp.timestamp() + 1)
    # event.timestamp = future
    now = int(time())
    event.timestamp = now
    try:
        updated_event = mh.misp.update_event(event, pythonify=True)
        if not isinstance(updated_event, dict):
            mh.logger.info(f"Successfully updated event {updated_event.id}")
        else:
            mh.logger.info(f"FAILED running misp.update_event: {updated_event}")
            
    except Exception as e:
        mh.logger.error(f"Error updating event {event.id} : {e}")
        mh.logger.warning(f"If it fails again it will be FATAL!")
        mh.logger.error(f"Sleeping for a couple seconds and trying again...")
        sleep(2)
        try:
            updated_event = mh.misp.update_event(event, pythonify=True)
            if not isinstance(updated_event, dict):
                mh.logger.info(f"Successfully updated event {updated_event.id}")
            else:
                mh.logger.info(f"FAILED running misp.update_event: {updated_event}")
        except Exception as e:
            mh.logger.error(f"FATAL Error updating event {event.id}: {e}")
            raise
    
    # Update the global "existing lists" every time there's a successful update
    if updated_event:
        mh.event_hosts = get_event_objects(mh, event, 'misphunter-host')
        mh.event_seeds = get_event_objects(mh, event, 'misphunter-seed')
        mh.event_certs = get_event_objects(mh, event, 'misphunter-cert')
        mh.event_dns = get_event_objects(mh, event, 'misphunter-dns')
        mh.event_malware = get_event_objects(mh, event, 'misphunter-malware')

    future = int(updated_event.timestamp.timestamp() + 1)
    updated_event.timestamp = future
    return updated_event

def update_existing_object(mh, obj):
    # Return MISPObject
    updated_object = False
    try:
        updated_object = mh.misp.update_object(obj, pythonify=True)
    except Exception as e:
        mh.logger.error(f"Error updating existing object {obj} : {e}")
    return updated_object
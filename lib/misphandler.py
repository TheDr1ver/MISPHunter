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


def get_logger():
    
    _log = logging.getLogger(__name__)
    _log.setLevel(logging.DEBUG)
    _log.handlers = []
    log_loc = "./misp-hunter.log"
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(funcName)s ln %(lineno)d - %(levelname)s - %(message)s")
    
    file_handler = logging.handlers.RotatingFileHandler(filename=log_loc, mode='a', maxBytes=30000000, backupCount=10)
    file_handler.setFormatter(formatter)
    _log.addHandler(file_handler)
    
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    _log.addHandler(console_handler)
    
    return _log

_log = get_logger()

def add_ips_to_cert_obj(cert_data, ips):
    existing_ips = []
    ip_attrs = cert_data.get_attributes_by_relation('cert-ip')
    # Check the IPs already in this cert_data object
    for ip in ip_attrs:
        if ip.value not in existing_ips:
            existing_ips.append(ip.value)
            if ip.value in ips:
                update_timestamps(ip)
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
                    update_timestamps(attr)
    return cert_data

def add_json_attr(checksum, raw_sorted_json_text, host_obj, json_type, comment=""):

    json_filename = str(checksum)+".json"
    _log.info(f"Saving raw JSON blob {json_filename} to host_obj {host_obj.uuid}...")
    pseudofile = BytesIO(raw_sorted_json_text.encode('utf-8'))
    new_attr = host_obj.add_attribute(json_type, value=json_filename, comment=comment, type='attachment', to_ids=False, data=pseudofile, distribution=5)
    update_timestamps(new_attr)
    _log.debug(f"Object updated. Returning {host_obj}")
    
    return host_obj

def blacklist_check_cert(misphunter, cert):
    # _log.debug(f"Checking misphunter-cert object {cert.uuid} to determine if it should be blacklisted.")
    cert_ips = cert.get_attributes_by_relation('cert-ip')
    sha256 = get_attr_val_by_rel(cert, 'cert-sha256')
    if len(cert_ips) <= 1:
        blacklist_attr = get_attr_obj_by_rel(cert, 'blacklisted')
        if int(blacklist_attr.value) == 0:
            _log.info(f"Cert {sha256} - {cert.uuid} only had {len(cert_ips)} IPs associated with it." 
                " Blacklisting cert from future pivots!")
            blacklist_attr.value = 1
            cert = update_existing_object(misphunter, cert)
            if 'new_auto_blacklists' not in misphunter.run_stats:
                misphunter.run_stats['new_auto_blacklists'] = {}
            if cert.event_id not in misphunter.run_stats['new_auto_blacklists']:
                misphunter.run_stats['new_auto_blacklists'][cert.event_id] = {}
            if 'misphunter-certs' not in misphunter.run_stats['new_auto_blacklists'][cert.event_id]:
                misphunter.run_stats['new_auto_blacklists'][cert.event_id]['misphunter-certs'] = []
            misphunter.run_stats['new_auto_blacklists'][cert.event_id]['misphunter-certs'].append(sha256)
    else:
        _log.debug(f"Cert {sha256} - {cert.uuid} had {len(cert_ips)} IPs associated with it. Leaving blacklist val alone!")
    return cert

def build_misphunter_cert(misphunter, cert, parent_obj, event, raw_data):
    
    parsed_data = raw_data['parsed']
    _log.info(f"Building a new misphunter-cert object for {parsed_data['fingerprint_sha256']}!")

    cert_temp = misphunter.misp.get_raw_object_template('misphunter-cert')
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
    comment=f"Certificate was seen on {ip}"
    cert_obj.add_reference(parent_obj.uuid, "derived-from", comment=comment)

    sha256 = parsed_data['fingerprint_sha256']
    if 'new_certs' not in misphunter.run_stats:
        misphunter.run_stats['new_certs'] = {str(event.id): [sha256]}
    elif str(event.id) not in misphunter.run_stats['new_certs']:
        misphunter.run_stats['new_certs'][str(event.id)] = [sha256]
    else:
        misphunter.run_stats['new_certs'][str(event.id)].append(sha256)

    for attr in cert_obj.Attribute:
        update_timestamps(attr)
    
    return cert_obj

def build_new_host_obj(misphunter, event, seed, ip):
    _log.info(f"MISP Object for {ip} does not exist. Building a new one.")
    try:
        raw_template = misphunter.misp.get_raw_object_template('misphunter-host')
    except Exception as e:
        _log.error(f"Could not get template for misphunter-host. Host {ip} WILL NOT BE ADDED: {e}")
        return False
    host_obj = MISPObject('misphunter-host', misp_objects_template_custom=raw_template)
    host_obj.is_new = True
    service = get_attr_val_by_rel(seed, 'service')
    search = get_attr_val_by_rel(seed, 'search-string')
    comment = f"Host derived from {service} seed: {search}"
    host_obj.add_attribute('host-ip', value=str(ip), type='ip-dst', to_ids=False, comment=comment)
    host_obj.add_attribute('blacklisted', value=str(0), type='boolean', to_ids=False)
    # Update timestamps
    for attr in host_obj.Attribute:
        update_timestamps(attr)
    # Define relationship
    ref_comment = f"{ip} derived from {service} search"
    host_obj.add_reference(seed.uuid, "derived-from", comment=ref_comment)

    if 'new_hosts' not in misphunter.run_stats:
        misphunter.run_stats['new_hosts'] = {str(event.id) : [ip]}
    elif str(event.id) not in misphunter.run_stats['new_hosts']:
        misphunter.run_stats['new_hosts'][str(event.id)] = [ip]
    else:
        misphunter.run_stats['new_hosts'][str(event.id)].append(ip)

    return host_obj

def check_all_certs(misphunter, cert, event):
    # Returns False if nothing found, otherwise returns the latest misphunter-cert MISPObject
    cert_data = False
    _log.info(f"Saving API queries by checking if cert already exists in database...")

    try:
        all_cert_data = misphunter.misp.search(controller="objects", object_name="misphunter-cert", value=cert, pythonify=True)
    except Exception as e:
        _log.error(f"FAILED attempt at searching for all existing certificates of value {cert}...")
        return False

    _log.debug(f"Found {len(all_cert_data)} certs matching value {cert}.")

    event_cert_uuids = []
    for event_cert in misphunter.event_certs:
        if event_cert.uuid not in event_cert_uuids:
            event_cert_uuids.append(event_cert.uuid)

    for obj in all_cert_data:
        if obj.uuid in event_cert_uuids:
            _log.info(f"Found a cert object that already lives in this exact event, so that's the one we'll use: {obj.uuid}")
            cert_data = obj
            break
        if cert_data == False:
            _log.debug(f"Found first cert object for {cert}: {obj.uuid}")
            cert_data = obj
        else:
            if int(obj.timestamp.timestamp()) > int(cert_data.timestamp.timestamp()):
                _log.debug(f"Found newer cert object [{obj.uuid}] to replace existing cert object {cert_data.uuid}")
                cert_data = obj
        
    if cert_data:
        if str(cert_data.event_id)!=str(event.id):
            _log.info(f"Found existing cert object {cert_data.uuid} from a different event. Cloning object for this event!")
            cert_data = clone_obj(misphunter, cert_data, event)
    
    return cert_data

def check_json_freshness(misphunter, host_obj, service):
    _log.info(f"First checking to see if we have an existing json blob new enough to avoid using an API query.")
    json_type = f"{service}-json"
    last_json = get_latest_attr_by_rel(host_obj, json_type)
    threshold_timestamp = int(time()) - (int(misphunter.update_threshold) * 60 * 60)
    if last_json:
        _log.info(f"{last_json.value} found of type {json_type}. Checking to see if it's new enough...")
        if int(last_json.last_seen.timestamp()) >= int(threshold_timestamp):
            _log.info(f"JSON timestamp of {int(last_json.last_seen.timestamp())} > {misphunter.update_threshold} hours ago ({int(threshold_timestamp)})."
                "good enough to reuse!")

            if not hasattr(host_obj, 'is_new'):
                host_obj.is_new = False

            if not host_obj.is_new:
                _log.debug(f"attempting to read {last_json.value}...")
                if not last_json.data:
                    _log.warning(f"Data missing from {last_json.value}... Trying some magic.")
                    last_json = misphunter.misp.get_attribute(last_json, pythonify=True)
                if not last_json.data:
                    _log.warning(f"Still no go. RETURNING FALSE!")
                    return False
                bytes_obj = last_json.data.read()
                last_json.data.seek(0)
                json_str = bytes_obj.decode('utf-8').replace("'", '"')
                try:
                    raw = json.loads(json_str)
                except Exception as e:
                    _log.error(f"Error attempting to load json: {e}")
                    _log.error(f"Something went wrong attempting to read {last_json.value}. Skipping re-use and "
                        "just going to hit the API again.")
                    return False
                # set misphunter_processed to make sure we're not re-processing this JSON object
                raw['misphunter_processed'] = True
                return raw
            else:
                _log.info(f"BUT WAIT - host_obj {host_obj.uuid} is_new! Better get a fresh JSON blob to be safe!")
                return False
        else:
            _log.info(f"It had a timestamp of {int(last_json.last_seen.timestamp())} and we wanted it to be > "
                f"{misphunter.update_threshold} hrs ago ({int(threshold_timestamp)}). Getting fresh JSON blob for comparison.")
            return False
    else:
        return False

def check_timer(misphunter, seed):
    # Returns seed with updated last_run time (or updated object timestamp in ignoring timers in debugging mode)
    _log.info(f"Checking event timer to see if seed {seed.uuid} is ready to update")
    update_seed_object = False
    now = int(time())

    last_run = get_seed_last_run(seed)

    # If no last_run time found, update event
    if last_run:
        last_run_time = int(last_run.timestamp())
    else:
        _log.info(f"Search does not have a record of when it was last run. Setting last run timestamp to 0.")
        last_run_time = 0
        if not misphunter.ignore_timers:
            seed.add_attribute('last-run', now, type="datetime", disable_correlation=True, pythonify=True)
        else:
            _log.info(f"ignore_timers flag is set, so not adding a last_run attribute to this event.")
        _log.debug(f"Setting update_seed_object to True.")
        update_seed_object = True

    freq = get_frequency(seed)

    # If no frequency time found, update event
    if freq:
        freq_time = int(freq) * 60 * 60
    else:
        _log.info(f"Search does not have a frequency set. Defaulting to 24 hours.")
        freq_time = 24 * 60 * 60
        # Ignore frequency attribute if running in debugger mode (avoids having to delete it every time)
        if not misphunter.ignore_timers:
            seed.add_attribute('update-freq', '24', type='text', disable_correlation=True, comment="Search is re-run every time this many hours have passed.", pythonify=True)
        else:
            _log.info(f"ignore_timers flag is set, so not adding a frequency attribute to this event.")
        _log.debug(f"Setting update_seed_object to True.")
        update_seed_object = True

    time_passed = now - int(last_run_time)
    # If no last_run_time set, this will always be true because time_passed/epoch is > whatever freq is set to.
    if time_passed >= freq_time:
        update_seed_object = True
        _log.info(f"{str(time_passed/60/60)} hours have passed. Time to run the search again!")
        # Ignore last_run attribute if running in debugger mode (avoids having to delete it every time)
        if not misphunter.ignore_timers:
            # Update the last_run value to now            
            for attr in seed.Attribute:
                if attr.object_relation == "last-run":
                    dtnow = datetime.utcfromtimestamp(now)
                    attr.value=dtnow
        else:
            _log.info(f"ignore_timers flag is set so not updating last_run attribute.")

        _log.debug(f"Setting misphunter.run_search to True...")
        misphunter.run_search = True

    if update_seed_object:
        _log.info(f"Updating MISP event with new run time or frequency.")
        # Seting new timestamp during debugging because otherwise nothing in the event will have changed
        if misphunter.ignore_timers:
            # event.timestamp = now
            seed.timestamp = now
        # event = misphunter.misp.update_event(event, pythonify=True)
        try:
            seed = misphunter.misp.update_object(seed, pythonify=True)
        except Exception as e:
            _log.error(f"Error attempting to update last-run timer for seed object {seed.uuid}: {e}")
            _log.debug(f"Running the search even though somehow the seed is messed up.")
            misphunter.run_search = True
    else:
        hours_passed = time_passed/60/60
        _log.info(f"{str(hours_passed)} hours have passed. Time limit has not been reached. No search will be run for {seed}.")
    
    if misphunter.ignore_timers:
        _log.info(f"...GOTCHA!! ignore_timers was set to True so all of that meant NOTHING and we're gonna run it anyway!")
        misphunter.run_search = True

    return seed

def clone_obj(misphunter, source_obj, event):
    if str(source_obj.event_id) == str(event.id):
        _log.info(f"Object {source_obj.uuid} does not need to be cloned because it already exists in this event.")
        _log.error(f"THIS IS LEGACY CODE")
        _log.error(f"THIS SHOULD NOT HAPPEN")
        _log.error(f"WE SHOULD HAVE ALREADY GRABBED THE OBJECT FROM THE EVENT BY NOW.")
        source_obj.is_new=False
        return source_obj
    else:
        _log.info(f"Discovered object [{source_obj.uuid}] has a different event_id ({source_obj.event_id}) than the event we're processing ({event.id}). Creating a new object")
    clone = deepcopy(source_obj)
    clone.uuid = str(uuid.uuid4())
    clone.event_id = event.id
    for attr in clone.Attribute:
        attr.uuid = str(uuid.uuid4())
        attr.event_id = event.id
        update_timestamps(attr)
    clone.is_new=True

    if 'new_clones' not in misphunter.run_stats:
        misphunter.run_stats['new_clones'] = {str(event.id) : [clone.uuid]}
    elif str(event.id) not in misphunter.run_stats['new_clones']:
        misphunter.run_stats['new_clones'][str(event.id)] = [clone.uuid]
    else:
        misphunter.run_stats['new_clones'][str(event.id)].append(clone.uuid)

    return clone

def get_all_attrs_by_rel(obj, rel):
    # _log.debug(f"Getting ALL Attribute OBJECTs from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        return attrs
    else:
        return []

def get_attr_val_by_rel(obj, rel):
    # _log.debug(f"Getting the VALUE of the FIRST attribute from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        attr_val = attrs[0].value
        # _log.debug(f"attribute value {attr_val} found in object {obj.uuid} by relationship {rel}.")
        return attr_val
    else:
        return False

def get_attr_obj_by_rel(obj, rel):
    # _log.debug(f"Getting the OBJECT of the FIRST attribute from object {obj.uuid} by relationship {rel}")
    attrs = obj.get_attributes_by_relation(rel)
    if len(attrs) > 0:
        attr = attrs[0]
        return attr
    else:
        return False

def get_event(misphunter, event_id):
    _log.info(f"Getting full MISPEvent Object for event {event_id}.")
    try: 
        event = misphunter.misp.get_event(event_id, pythonify=True)
    except Exception as e:
        _log.error(f"Something went wrong trying to get misp event {event_id}: {e}")
        return False
    return event

def get_all_event_seeds(misphunter):
    _log.info(f"Getting all events and their associated misphunter-seeds.")
    all_event_seeds = {}
    try:
        seeds = misphunter.misp.search(controller="objects", object_name="misphunter-seed", pythonify=True)
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-seed objects from all events: {e}")
        return False

    for seed in seeds:
        enabled = get_attr_val_by_rel(seed, 'enabled')
        if enabled=="0":
            continue
        if seed.event_id not in all_event_seeds:
            all_event_seeds[str(seed.event_id)] = []
        if seed not in all_event_seeds[str(seed.event_id)]:
            
                all_event_seeds[str(seed.event_id)].append(seed)
    _log.info(f"Found {len(all_event_seeds)} events with {len(seeds)} misphunter-seeds")
    _log.debug(f"{all_event_seeds.keys()}")
    return all_event_seeds

def get_event_seeds(misphunter, event):
    # _log.debug(f"Getting all seed objects associated with event {event.id}.")
    event_seeds = []
    try:
        event_seeds = event.get_objects_by_name("misphunter-seed")
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-seed objects from event {event.id}: {e}")
    misphunter.event_seeds = event_seeds
    _log.debug(f"Found {len(misphunter.event_seeds)} existing misphunter-seed objects in event {event.id}!")

def get_event_hosts(misphunter, event):
    # _log.debug(f"Getting misphunter-hosts from event {event.id}")
    event_hosts = []
    try:
        event_hosts = event.get_objects_by_name("misphunter-host")
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-host objects from event {event.id}: {e}")
    misphunter.event_hosts = event_hosts
    _log.debug(f"Found {len(misphunter.event_hosts)} existing misphunter-host objects in event {event.id}!")

def get_event_certs(misphunter, event):
    # _log.debug(f"Getting misphunter-certs from event {event.id}")
    event_certs = []
    try:
        event_certs = event.get_objects_by_name("misphunter-cert")
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-cert objects from event {event.id}: {e}")
    misphunter.event_certs = event_certs
    _log.debug(f"Found {len(misphunter.event_certs)} existing misphunter-cert objects in event {event.id}!")

def get_event_dns(misphunter, event):
    # _log.debug(f"Getting misphunter-dns objects from event {event.id}")
    event_dns = []
    try:
        event_dns = event.get_objects_by_name("misphunter-dns")
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-dns objects in event {event.id}: {e}")
    misphunter.event_dns = event_dns
    _log.debug(f"Found {len(misphunter.event_dns)} existing misphunter-dns objects in event {event.id}!")

def get_event_malware(misphunter, event):
    # _log.debug(f"Getting misphunter-malware objects from event {event.id}")
    event_malware = []
    try:
        event_malware = event.get_objects_by_name("misphunter-malware")
    except Exception as e:
        _log.error(f"Something went wrong trying to get misphunter-malware objects from event {event.id}: {e}")
    misphunter.event_malware = event_malware
    _log.debug(f"Found {len(misphunter.event_malware)} existing misphunter-malware objects in event {event.id}!")

def get_frequency(seed):
    _log.info(f"Getting the update frequency of seed {seed.uuid}.")
    freq = False
    freqs = seed.get_attributes_by_relation('update-freq')
    if len(freqs) > 0:
        freq = freqs[0].value
        _log.info(f"Search frequency for seed {seed.uuid} set to run once every {freq} hours.")
        return freq
    return freq

def get_global_blocks(misphunter):
    _log.info(f"Searching MISP for globally blocked IPs")
    global_blocks=[]
    block_objects = misphunter.misp.search(controller="objects", object_name="misphunter-host-blacklist", pythonify=True)
    for bo in block_objects:
        bo_global_blocks = bo.get_attributes_by_relation('global-block')
        for bogb in bo_global_blocks:
            if bogb.value not in global_blocks:
                global_blocks.append(bogb.value)
    
    _log.info(f"Found {len(global_blocks)} global blocks: {global_blocks}")
    return global_blocks

def get_host_obj(misphunter, event, seed, ip):
    # First, check if this IP shows up in any misphunter-host objects already living in this event.
    for host_obj in misphunter.event_hosts:
        host_ip = get_attr_val_by_rel(host_obj, 'host-ip')
        if host_ip == ip:
            _log.info(f"Found existing object already living in this event with host-ip {ip}: {host_obj.uuid}. Updating timestamp and returning that.")
            ip_attr = get_attr_obj_by_rel(host_obj, 'host-ip')
            update_timestamps(ip_attr)
            return host_obj

    # Then, check if this IP shows up in any recently-updated misphunter-host objects living on the server.
    _log.info(f"No existing object found in event {event.id} for IP {ip}. Searching the rest of the instance...")
    existing_obj = search_recent_updated_objects(misphunter, event, seed, value=ip)
    if not existing_obj:
        _log.info(f"No existing object found server-wide. Building new host_obj.")
        host_obj = build_new_host_obj(misphunter, event, seed, ip)
    else:
        if existing_obj.is_new:
            service = get_attr_val_by_rel(seed, 'service')
            ref_comment = f"{ip} derived from {service} search"
            existing_obj.add_reference(seed.uuid, "derived-from", comment=ref_comment)
        return existing_obj
            
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

def get_local_blocks(misphunter, event):
    global_blocks = misphunter.global_blocks
    
    _log.info(f"Getting local block list for {event.info}")
    
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
                        local_blocks.append(attr.value)

    return local_blocks

def get_seed_last_run(seed):
    last_run = False
    last_runs = seed.get_attributes_by_relation('last-run')
    if len(last_runs) > 0:
        last_run = last_runs[0].value
        _log.info(f"seed last ran: {last_run}")
        return last_run
    _log.info(f"seed last ran: {last_run}")
    return last_run

def search_recent_updated_objects(misphunter, event, seed, value=""):
    # This is called by the *_search_ip section of various plugins.
    #   It returns False if no object was discovered that was updated 
    #   in the last {misphunter.update_threshold} hours. Otherwise it
    #   returns MISPObject, which skips all the enrichment processes it
    #   would otherwise go through.
    newest_obj = False
    service = get_attr_val_by_rel(seed, 'service')
    

    min_epoch = int(time()) - (misphunter.update_threshold * 60 * 60)
    # dt = datetime.fromtimestamp(max_epoch)

    if service in misphunter.host_seed_services:
        _log.info(f"Searching MISP instance for misphunter-host objects with value {value} "\
            f"that were updated in the last {misphunter.update_threshold} hours to save API queries.")
        try:
            misphunter_hosts = misphunter.misp.search(controller="objects", object_name="misphunter-host", 
                value=value, timestamp=min_epoch, with_attachments=True, pythonify=True)
            _log.info(f"Found {len(misphunter_hosts)} results!")
        except Exception as e:
            _log.error(f"Something went wrong trying to get misphunter-host objects server-wide: {e}")
            return False
        for host_obj in misphunter_hosts:
            host_ip = get_attr_val_by_rel(host_obj, 'host-ip')
            host_attr = get_attr_obj_by_rel(host_obj, 'host-ip')
            host_obj_last_seen = int(host_attr.last_seen.timestamp())
            if host_obj_last_seen < min_epoch:
                _log.info(f"Skipping {host_obj.uuid} because the IP was last seen too long ago.")
                _log.debug(f"Last_seen was {host_obj_last_seen} and we need it to be greater than {min_epoch} to "
                    f"use it.")
                continue
            else:
                _log.info(f"Looks like we're good to go with {host_obj.uuid}")
                _log.debug(f"Last_seen was {host_obj_last_seen} and we need it to be less than {min_epoch} to "
                    f"skip using it again")
            if host_ip == value:
                if not newest_obj:
                    newest_obj = host_obj
                    newest_attr = get_attr_obj_by_rel(newest_obj, 'host-ip')
                    newest_obj_last_seen = int(newest_attr.last_seen.timestamp())
                    continue
                if host_obj_last_seen >= newest_obj_last_seen:
                    newest_obj = host_obj
                    newest_attr = get_attr_obj_by_rel(newest_obj, 'host-ip')
                    newest_obj_last_seen = int(newest_attr.last_seen.timestamp())

    # TODO - Future stuff - handle other types of seeds
    '''
    elif service in misphunter.dns_seed_services:
        try:
            misphunter_dnses = misphunter.misp.search(controller="objects", object_name="misphunter-dns", value=value, timestamp=min_epoch, with_attachments=True, pythonify=True)
        except Exception as e:
            _log.error(f"Something went wrong trying to get misphunter-dns objects server-wide: {e}")
            return False
        for dns_obj in misphunter_dnses:
            domain = get_attr_val_by_rel(dns_obj, 'domain')
            if domain == value:
                if not newest_obj:
                    newest_obj = dns_obj
                    continue
                if int(dns_obj.timestamp.timestamp()) >= int(newest_obj.timestamp.timestamp()):
                    newest_obj = host_obj
    '''
    if newest_obj:
        # Check if this object belongs to the event we're processing, otherwise clone it.
        if str(newest_obj.event_id) != str(event.id):
            _log.info(f"Most-recently updated object is from a different event - [{newest_obj.event_id} vs {event.id}]")
            _log.info(f"Cloning latest version of object {newest_obj.uuid} for adding to into event {event.id}")
            newest_obj = clone_obj(misphunter, newest_obj, event)
        else:
            newest_obj.is_new=False

    return newest_obj

def update_timestamps(attr):
    _log.debug(f"Updating timestamps for attribute {attr.value}.")
    epoch = int(time())
    if not hasattr(attr, 'timestamp'):
        attr.timestamp = epoch
        # _log.debug(f"Updated {attr.value} timestamp to {epoch}")
    if not hasattr(attr, 'first_seen'):
        attr.first_seen = attr.timestamp
        # _log.debug(f"Set {attr.value} first_seen to {attr.timestamp}")
    if not hasattr(attr, 'last_seen'):
        attr.last_seen = epoch
        # _log.debug(f"Set {attr.value} last_seen to {epoch}")
    if epoch > int(attr.last_seen.timestamp()):
        attr.last_seen = epoch 
        # _log.debug(f"Updated {attr.value} last_seen to {epoch}")
    return attr

def update_event(misphunter, event):
    updated_event = False
    # future = int(event.timestamp.timestamp() + 1)
    # event.timestamp = future
    now = int(time())
    event.timestamp = now
    try:
        updated_event = misphunter.misp.update_event(event, pythonify=True)
        if not isinstance(updated_event, dict):
            _log.info(f"Successfully updated event {updated_event.id}")
        else:
            _log.info(f"FAILED running misp.update_event: {updated_event}")
            
    except Exception as e:
        _log.error(f"Error updating event {event.id} : {e}")
        _log.warning(f"If it fails again it will be FATAL!")
        _log.error(f"Sleeping for a couple seconds and trying again...")
        sleep(2)
        try:
            updated_event = misphunter.misp.update_event(event, pythonify=True)
            if not isinstance(updated_event, dict):
                _log.info(f"Successfully updated event {updated_event.id}")
            else:
                _log.info(f"FAILED running misp.update_event: {updated_event}")
        except Exception as e:
            _log.error(f"FATAL Error updating event {event.id}: {e}")
            raise
    
    # Update the global "existing lists" every time there's a successful update
    if updated_event:
        get_event_seeds(misphunter, event)
        get_event_hosts(misphunter, event)
        get_event_certs(misphunter, event)
        get_event_dns(misphunter, event)
        get_event_malware(misphunter, event)

    future = int(updated_event.timestamp.timestamp() + 1)
    updated_event.timestamp = future
    return updated_event

def update_existing_object(misphunter, obj):
    # Return MISPObject
    updated_object = False
    try:
        updated_object = misphunter.misp.update_object(obj, pythonify=True)
    except Exception as e:
        _log.error(f"Error updating existing object {obj} : {e}")
    return updated_object
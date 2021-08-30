import logging, logging.handlers
import sys

from pprint import pformat

from . import helper, misphandler

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

def auto_blacklist(misphunter, event):
    
    _log.debug(f"Determining if any objects should be automatically blacklisted based on their pivot results.")
    all_certs = event.get_objects_by_name('misphunter-cert')
    for cert in all_certs:
        cert = misphandler.blacklist_check_cert(misphunter, cert)
    return event

def cert_pivot(misphunter, host_obj, event, seed):

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
        _log.info(f"Found {len(host_certs)} new cert(s) for pivoting in new object: "\
            f"{pformat(host_certs)}")

    # Pivot on all the hashes associated with this specific host
    for cert_hash in host_certs:
        new_cert_obj = True
        _log.info(f"Pivoting on cert {cert_hash}...")
        # Returns MISPObject misphunter-cert
        cert_data = helper.search_cert_data(misphunter, cert_hash, host_obj, event)
        if not cert_data:
            _log.error(f"Something went wrong attempting to get certificate data. Skipping cert {cert_hash} entirely!")
            continue

        # Check if this cert object is new to this event or not
        for existing_obj in misphunter.event_certs:
            if cert_data.uuid == existing_obj.uuid:
                _log.info(f"This certificate is not new to this event. Setting new_cert_obj to False.")
                new_cert_obj = False

        # Check cert_data timestamp - if less than update threshold, update IPs.
        update_ips = helper.check_update_threshold(misphunter, cert_data)
        if update_ips or new_cert_obj:
            if update_ips:
                _log.debug(f"check_update_threshold() returned True - searching again for IPs!")
            if new_cert_obj:
                _log.debug(f"new_cert_obj is set to True, which means this cert is new to this event, which means "
                    "we're once again searching for related IPs!")
            # Find IPs associated with this cert
            cert_data = helper.search_cert_hosts(misphunter, cert_data, host_ip)

        # Update object/event
        if new_cert_obj:
            _log.info(f"misphunter-cert object {cert_data.uuid} is apparently new to event {event.id}. "
                "Updating event!")
            event.add_object(cert_data, pythonify=True)
            updated_event = misphandler.update_event(misphunter, event)
            if not updated_event:
                _log.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object.")
                _log.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
            else:
                event = updated_event
        else:
            _log.info(f"misphunter-cert object {cert_data.uuid} is NOT new to event {event.id}. "
                f"Updating object first...")
            updated_object = misphandler.update_existing_object(misphunter, cert_data)
            if not updated_object:
                _log.error(f"Error updating existing cert-object {cert_data.uuid} in event {event.id}. Returned "
                    "False instead of MISPEvent Object.")
                _log.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
                continue
            else:
                cert_data = updated_object
                _log.info(f"...then getting a fresh copy of event {event.id} and updating it!")
                updated_event = misphandler.get_event(misphunter, cert_data.event_id)
                if not updated_event:
                    _log.error(f"Simply GETTING event {event.id} FAILED. Returned False instead of MISPEvent Object. "
                        "Using pre-existing event going forward.")
                    _log.debug(f"Skipping over cert {cert_hash} entirely... FIGURE OUT WHAT WENT WRONG!")
                    continue
                else:
                    event = updated_event
        # Add all finished cert_data objects to a big list for IP processing
        if cert_data not in all_cert_data:
            all_cert_data.append(cert_data)

    _log.info(f"Finished processing certs for host object {host_obj.uuid}.")

    host_ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')

    event = process_cert_ips(misphunter, all_cert_data, seed, event, host_ip)

    return event

def process_cert_ips(misphunter, all_cert_data, seed, event, host_ip):
    # ignore IPs arleady in this event to avoid getting caught in a loop
    existing_event_hosts = []
    for host in misphunter.event_hosts:
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
                    _log.debug(f"Ignoring {cert_ip} associated with this cert because it's already been processed.")
        if len(cert_ips) <= 0:
            _log.debug(f"No IPs were found associatd with misphunter-cert object {cert_obj.uuid}. Checking next cert!")
            continue
        else:
            updated_event = process_hosts(misphunter, event, seed, cert_ips)
            if not updated_event:
                _log.error(f"Something went wrong running process_hosts() for cert_ips: {cert_ips}. Skipping cert_obj {cert_obj.uuid}!")
                _log.debug(f"Using previous iteration of event...")
                _log.debug(f"FIGURE OUT WHY process_hosts() FAILED AGAINST THE ABOVE GROUP OF cert_ips!")
                continue
            else:
                event = updated_event
    _log.info(f"All {len(all_cert_data)} cert objects processed for {host_ip}. Updating event and MOVING ON!")
    # Update event before exiting the routine
    updated_event = misphandler.update_event(misphunter, event)
    if not updated_event:
        _log.error(f"Something went wronng trying to update the final MISPEvent of the process_cert_ips() routine!")
        _log.debug(f"returning untouched event that was sent to the process_cert_ips routine. FIGURE IT OUT!")
    else:
        event = updated_event
    return event
        
def process_seeds(misphunter, seeds, event):
    for seed in seeds:
        misphunter.run_search = False
        # Check timer for each seed to make sure we're not running prematurely
        # Also sets self.run_search to True if it's time to run the seed search again
        seed = misphandler.check_timer(misphunter, seed)
        if misphunter.run_search:
            seed_service = misphandler.get_attr_val_by_rel(seed, 'service')
            if not seed_service:
                _log.error(f"No service found associated with seed object {seed.uuid}. Skipping seed!")
                continue
            seed_search = misphandler.get_attr_val_by_rel(seed, 'search-string')
            if not seed_search:
                _log.error(f"No search string found associated with seed object {seed.uuid}. Skipping seed!")
                continue
            misphunter.logger.debug(f"Timer checks have passed. Processing seed for [{seed_service}] - {seed_search}...")
            # _log.debug(f"Checking if {seed_service} is in misphunter.host_seed_services - {misphunter.host_seed_services}")
            if seed_service in misphunter.host_seed_services:
                ips = helper.run_host_seed(misphunter, seed_search, seed_service)
                if len(ips) <= 0:
                    _log.error(f"No IPs were found running {seed_service} search {seed_search}.Skipping seed!")
                    continue
                else:
                    updated_event = process_hosts(misphunter, event, seed, ips)
                    if updated_event:
                        event = updated_event
                    else:
                        _log.error(f"running process_hosts with seed {seed.uuid} and ips {ips} FAILED. Event NOT updated..")


            # TODO - FUTURE - add different types of seed results to be processed
            # elif seed_service in misphunter.dns_seed_services:
            #     domains = helper.run_dns_seed(misphunter, seed_search, seed_service)

    # Update event before exiting the routine
    updated_event = misphandler.update_event(misphunter, event)
    if not updated_event:
        _log.error(f"Something went wronng trying to update the final MISPEvent of the process_seeds() routine!")
        _log.debug(f"returning untouched event that was sent to the process_seeds routine. FIGURE IT OUT!")
    else:
        event = updated_event
    return event

def process_hosts(misphunter, event, seed, ips):

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
    blocks = misphandler.get_local_blocks(misphunter, event)
    _log.debug(f"All blocks: {blocks}")
    
    # Loop through each IP found by the Seed Object's search string
    _log.info(f"Processing {len(ips)} discovered hosts: {ips}")
    for ip in ips:
        # Check IP against local and global blocks
        if helper.check_block(misphunter, ip, blocks):
            continue
        _log.info(f"Processing IP {ip}")
        # get existing misphunter-host object or create new one
        host_obj = misphandler.get_host_obj(misphunter, event, seed, ip)
        # host_obj returns .is_new=True if it's a newly built host object, or if it's a new clone
        # of an existing object.
        if not host_obj:
            _log.error(f"After processing IP {ip} with get_host_obj() something still managed to go wrong. Skipping this host.")
            continue

        # Enrich the Host Object by extracting IOCs, comparing changes, etc.
        host_obj = helper.enrich_host_obj(misphunter, event, seed, host_obj)

        # Check if this object existed when we first started processing this event
        for existing_obj in misphunter.event_hosts:
            if host_obj.uuid == existing_obj.uuid:
                _log.info(f"host object {host_obj.uuid} found already existing in this event.")
                new_host_obj = False

        # Check if host_obj is new (e.g. a cloned or newly-built object)
        if hasattr(host_obj, 'is_new'):
            if host_obj.is_new:
                _log.info(f"host object {host_obj.uuid} is new (newly built or cloned from another event).")
                new_host_obj = True

        # If this host object is new to this event, add it to the event and get the latest version of the event.
        if new_host_obj:
            event.add_object(host_obj, pythonify=True)
            updated_event = misphandler.update_event(misphunter, event)
            if not updated_event:
                _log.error(f"Error updating event {event.id}. Returned False instead of MISPEvent Object. Using pre-existing event going forward.")
            else:
                event = updated_event

        # If this host object is not new to this event update the object, then re-pull the whole event for good measure.
        else:
            updated_object = misphandler.update_existing_object(misphunter, host_obj)
            if not updated_object:
                _log.error(f"Error updating existing object {host_obj.uuid} in event {event.id}. Returned False instead of MISPEvent Object.")
            else:
                host_obj = updated_object
                updated_event = misphandler.get_event(misphunter, updated_object.event_id)
                if not updated_event:
                    _log.error(f"SIMPLY GETTING event {event.id} FAILED. Returned False instead of MISPEvent Object. Using pre-existing event going forward.")
                else:
                    # Update the global "existing lists" every time there's a successful MISPObject-only update
                    misphandler.get_event_seeds(misphunter, event)
                    misphandler.get_event_hosts(misphunter, event)
                    misphandler.get_event_certs(misphunter, event)
                    misphandler.get_event_dns(misphunter, event)
                    misphandler.get_event_malware(misphunter, event)
                    event = updated_event

        # Assuming cert_pivoting is enabled, attempt to find more hosts sharing the same certificate as this IP.
        if misphunter.cert_pivoting:
            updated_event = cert_pivot(misphunter, host_obj, event, seed)
            if not updated_event:
                _log.error(f"Something bad happened while trying to run cert_pivot(). Event was not updated.")
            else:
                event = updated_event

    return event

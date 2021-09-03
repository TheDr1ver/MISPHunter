import hashlib
import ipaddress
import json
import logging, logging.handlers
import re
import sys

from collections import OrderedDict
from datetime import datetime
import iocextract
from ipaddress import ip_address, ip_network
from itertools import chain, starmap
from pprint import pformat
from pymisp import MISPObject
from six import string_types
from time import time

from dateparser.search import search_dates

from . import censys, misphandler, shodan

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

def add_iocs_to_object(iocs, checksum, host_obj):
    _log.info(f"Processing IOCs to add them to host object: \n{iocs}")
    # Get existing IOCs from object
    existing_iocs = {'ips': [], 'emails': [], 'domains': [], 'certificates': [], 'urls': []}
    for attr in host_obj.Attribute:
        if attr.type == 'ip-dst':
            if attr.value not in existing_iocs['ips']:
                existing_iocs['ips'].append(attr.value)
        if attr.type == 'email-src':
            if attr.value not in existing_iocs['emails']:
                existing_iocs['emails'].append(attr.value)
        if attr.type == 'domain':
            if attr.value not in existing_iocs['domains']:
                existing_iocs['domains'].append(attr.value)
        if attr.type == 'x509-fingerprint-sha256':
            if attr.value not in existing_iocs['certificates']:
                existing_iocs['certificates'].append(attr.value)
        if attr.type == 'url':
            if attr.value not in existing_iocs['urls']:
                existing_iocs['urls'].append(attr.value)

    for ioc_type, ioc_list in iocs.items():
        if ioc_type == 'ips':
            for ip in ioc_list:
                # check if IP already exists in object. If not, add it.
                if ip not in existing_iocs['ips']:
                    _log.debug(f"Adding IP {ip} to host object.")
                    comment = f"Harvested from {checksum}.json:\n"
                    comment += iocs['context'][ip]
                    attr = host_obj.add_attribute('extracted-ip', value=str(ip), comment=comment, type='ip-dst', to_ids=False, distribution=5)
                    misphandler.update_timestamps(attr)
                else:
                    existing_ips = existing_iocs['ips']
                    _log.debug(f"IP {ip} is already in existing list of IPs for this object: {existing_ips}")
        if ioc_type == 'emails':
            for email in ioc_list:
                # Check if email already exists in object. If not, add it.
                if email not in existing_iocs['emails']:
                    _log.debug(f"Adding email {email} to host object.")
                    comment = f"Harvested from {checksum}.json:\n"
                    comment += iocs['context'][email]
                    attr = host_obj.add_attribute('extracted-email', value=str(email), comment=comment, type='email-src', to_ids=False, distribution=5)
                    misphandler.update_timestamps(attr)
                else:
                    existing_emails = existing_iocs['emails']
                    _log.debug(f"Email {email} is already in existing list of emails for this object: {existing_emails}")
        if ioc_type == 'domains':
            for domain in ioc_list:
                # Check if domain already exists in object. If not, add it.
                if domain not in existing_iocs['domains']:
                    _log.debug(f"Adding domain {domain} to host object.")
                    comment = f"Harvested from {checksum}.json:\n"
                    comment += iocs['context'][domain]
                    attr = host_obj.add_attribute('extracted-domain', value=str(domain), comment=comment, type='domain', to_ids=False, distribution=5)
                    misphandler.update_timestamps(attr)
                else:
                    existing_domains = existing_iocs['domains']
                    _log.debug(f"Domain {domain} is already in existing list of domains for this object: {existing_domains}")
        if ioc_type == 'certificates':
            for cert in ioc_list:
                # Check if cert already exists in object. If not, add it.
                if cert not in existing_iocs['certificates']:
                    _log.debug(f"Adding certificate {cert} to host object.")
                    comment = f"Harvested from {checksum}.json\n"
                    comment += iocs['context'][cert]
                    attr = host_obj.add_attribute('extracted-certificate', value=str(cert), comment=comment, type='x509-fingerprint-sha256', to_ids=False, distribution=5)
                    misphandler.update_timestamps(attr)
                else:
                    existing_certs = existing_iocs['certificates']
                    _log.debug(f"Cert {cert} is already in existing list of certificates for this object: {existing_certs}")
        if ioc_type == 'urls':
            for url in ioc_list:
                # check if URL already exists in object. if not, add it.
                if url not in existing_iocs['urls']:
                    _log.debug(f"Adding URL {url} to host object.")
                    comment = f"Harvested from {checksum}.json\n"
                    comment += iocs['context'][url]
                    attr = host_obj.add_attribute('extracted-url', value=str(url), comment=comment, type='url', to_ids=False, distribution=5)
                    misphandler.update_timestamps(attr)
                else:
                    existing_urls = existing_iocs['urls']
                    _log.debug(f"URL {url} is already in existing list of URLs for this object: {existing_urls}")

    return host_obj

def build_cert_host_rels(event, rel_index):
    # rel_index = {
    #     'used-by' : {
    #         'abcd-abcd-abcd-abcd': ['wxyz-wxyz-wxyz-wxyz']
    #      },
    #     'all_hosts': {
    #         '192.168.1.1': [fedg-fedg-fedg-fedg]
    #      },
    #     'all_certs': {
    #         'asdfasdfasdfasdfasdf': [degf-degf-degf-degf]
    #      },
    # }
    # 
    _log.info(f"Building cert -> host relationships...")
    num_certs = 0
    num_new_rels = 0
    num_existing_rels = 0
    for obj in event.Object:
        if obj.name == "misphunter-cert":
            num_certs += 1
            sha256 = misphandler.get_attr_val_by_rel(obj, 'cert-sha256')
            cert_uuid = obj.uuid
            related_ips = misphandler.get_all_attrs_by_rel(obj, 'cert-ip')
            for attr in related_ips:
                ip = attr.value
                if ip in rel_index['all_hosts']:
                    host_uuid = rel_index['all_hosts'][ip]
                    if 'used-by' not in rel_index:
                        _log.debug(f"Found no relationships in event {event.id} where 'used-by' was a relationship_type.")
                        ref = obj.add_reference(host_uuid, 'used-by')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] used by cert {sha256} [{cert_uuid}].")
                        # rel_index['used-by'] = {host_uuid : [cert_uuid]}
                        rel_index['used-by'] = {cert_uuid : [host_uuid]}
                    # elif host_uuid not in rel_index['used-by']:
                    elif cert_uuid not in rel_index['used-by']:
                        ref = obj.add_reference(host_uuid, 'used-by')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] used by cert {sha256} [{cert_uuid}].")
                        # rel_index['used-by'][host_uuid] = [cert_uuid]
                        rel_index['used-by'][cert_uuid] = [host_uuid]
                    # elif cert_uuid not in rel_index['used-by'][host_uuid]:
                    elif host_uuid not in rel_index['used-by'][cert_uuid]:
                        ref = obj.add_reference(host_uuid, 'used-by')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] used by cert {sha256} [{cert_uuid}].")
                        # rel_index['used-by'][host_uuid].append(cert_uuid)
                        rel_index['used-by'][cert_uuid].append(host_uuid)
                    else:
                        num_existing_rels += 1
                        # _log.debug(f"Relationship between host {ip} [{host_uuid}] and cert {sha256} [{cert_uuid}] already exists!")
    # _log.debug(f"rel_index['used-by']:")
    # _log.debug(f"{pformat(rel_index['used-by'])}")
    # _log.debug(f"\n\nrel_index:\n\n")
    # _log.debug(f"{pformat(rel_index)}")
    _log.info(f"Found {num_certs} seeds in this event with {num_existing_rels} existing relationships. Added {num_new_rels} new relationships!")
    return rel_index

def build_seed_host_rels(event, rel_index):
    _log.info(f"Building seed -> host relationships...")
    num_seeds = 0
    num_new_rels = 0
    num_existing_rels = 0
    for obj in event.Object:
        if obj.name == "misphunter-seed":
            num_seeds += 1
            seed_uuid = obj.uuid
            related_ips = misphandler.get_all_attrs_by_rel(obj, 'found-host')
            for attr in related_ips:
                ip = attr.value
                if ip in rel_index['all_hosts']:
                    host_uuid = rel_index['all_hosts'][ip]
                    if 'query-returned' not in rel_index:
                        _log.debug(f"Found no relationships in event {event.id} where 'query-returned' was a relationship_type.")
                        ref = obj.add_reference(host_uuid, 'query-returned')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] found by seed [{seed_uuid}]")
                        rel_index['query-returned'] = {seed_uuid : [host_uuid]}
                    elif seed_uuid not in rel_index['query-returned']:
                        ref = obj.add_reference(host_uuid, 'query-returned')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] found by seed [{seed_uuid}]")
                        rel_index['query-returned'][seed_uuid] = [host_uuid]
                    elif host_uuid not in rel_index['query-returned'][seed_uuid]:
                        ref = obj.add_reference(host_uuid, 'query-returned')
                        num_new_rels += 1
                        _log.debug(f"Adding relationship - host {ip} [{host_uuid}] found by seed [{seed_uuid}]")
                        rel_index['query-returned'][seed_uuid].append(host_uuid)
                    else:
                        num_existing_rels += 1
                        # _log.debug(f"Relationship between host {ip} [{host_uuid}] and seed [{seed_uuid}] already exists!")
    _log.info(f"Found {num_seeds} seeds in this event with {num_existing_rels} existing relationships. Added {num_new_rels} new relationships!")
    return rel_index

def check_block(misphunter, ip, blocks):
    skip = False
    for net in blocks:
        if ip_address(ip) in ip_network(net):
            # Drop all IPs matching local and global blocklists (local_blocks and misphunter.global_blocks)
            _log.info(f"IP {ip} found in blocked IP/CIDR {net}. Skipping!")
            skip = True
    return skip

def check_update_threshold(misphunter, obj):
    # returns True if object needs to be updated, False if not
    if not hasattr(obj, 'timestamp'):
        return True
    _log.debug(f"Checking if object {obj.uuid} should be updated.")
    min_hours = int(misphunter.update_threshold)
    min_time = int(time()) - (min_hours * 60 * 60)
    obj_time = int(obj.timestamp.timestamp())
    diff_secs = min_time - obj_time
    diff_hours = diff_secs / 60 / 60
    # if obj_time < min_time:
    if diff_hours >= min_hours:
        _log.debug(f"YES! It has been {diff_hours} hours since {obj.uuid} has been updated! "
            f"min_time: {min_time} obj_time: {obj_time} min_hours: {min_hours}")
        return True
    else:
        _log.debug(f"NO! It has ONLY been {diff_hours} hours since {obj.uuid} has been updated! "
            f"min_time: {min_time} obj_time: {obj_time} min_hours: {min_hours}")
        return False

def clean_junk_domains(domains, context, cleanup, misp):
    if 'domains' in cleanup.keys():
        domains = junk_iocs(domains, context, cleanup['domains'])

    if domains == []:
        _log.debug(f"All domains were scrubbed. Returning empty list!")
        return domains
    # Make sure domains from "Top Anything" lists are removed
    warning_lists = misp.values_in_warninglist(domains)
    _log.debug(f"Warning Lists: {warning_lists}")
    if len(warning_lists) > 0:
        for domain, lists in warning_lists.items():
            for l in lists:
                if l['name'].startswith('Top '):
                    name = l['name']
                    _log.debug(f"{domain} showed up on '{name}'. Removing from list.")
                    domains.remove(domain)
                    break
    return domains

def clean_keys(misphunter, unsorted_json, hunt):
    # Pulls keys from plugins that should be ignored when processing JSON diffs
    _log.info(f"Removing ignored keys from comparison...")

    igkeys = {
        "censys-v1": censys.censys_v1_clean_json_keys(),
        "censys-v2": censys.censys_v2_clean_json_keys(),
        "shodan": shodan.shodan_clean_json_keys()
    }

    if hunt not in misphunter.ignored_json_keys:
        misphunter.ignored_json_keys[hunt] = igkeys[hunt]

    ignored_keys = misphunter.ignored_json_keys[hunt]
                                    
    copy_blob = unsorted_json.copy()
    for k, v in copy_blob.items():
        for k2 in ignored_keys:
            if k.endswith(k2):
                _log.info(f"Removing unwanted key {k}...")
                _log.debug(f"{copy_blob[k]}")
                unsorted_json.pop(k)

    return unsorted_json

def dict_compare(dict1, dict2):
    d1_missing_keys = dict2.keys()-dict1
    d2_missing_keys = dict1.keys()-dict2
    diff_val_keys = [key for key in dict1.keys() & dict2 if dict1[key] != dict2[key]]

    comment = ""
    if len(d1_missing_keys) > 0:
        comment += f"Added keys: {str(list(d1_missing_keys))}\n"
    if len(d2_missing_keys) > 0:
        comment += f"Removed keys: {str(list(d2_missing_keys))}\n"
    if len(diff_val_keys) > 0:
        comment += f"Modified keys: {str(diff_val_keys)}\n"
    if comment == "":
        comment = "OOPS! Apparently these results are identical to the last ones."

    return comment

def enrich_host_obj(misphunter, event, seed, host_obj):

    host_ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
    service = misphandler.get_attr_val_by_rel(seed, 'service')
    _log.info(f"Enriching Host Object {host_obj.uuid} - {host_ip} - using seed service {service}")

    # raw = parsed JSON object that can be treated as a dict
    raw = search_ip(misphunter, event, seed, host_obj)

    # if 'misphunter_processed' key IS set, it means we've already handled this JSON
    #   blob before. No need to re-process it. Remove the key so the checksum stays the same
    #   and pass on as-is.
    # if 'misphunter_processed' key is NOT set, do all the pre-processing stuff
    
    if 'misphunter_processed' not in raw:
        # Cleanup raw JSON response for processing
        raw_sorted_json_text = sort_raw_json(misphunter, raw, service)
        
        # Usually skipping this because the sub_dates logic takes way too long
        if misphunter.remove_dates:
            raw_sorted_json_text = remove_dates(raw_sorted_json_text)

        checksum = md5_data(raw_sorted_json_text)

        # Load the blob for upcoming procesing/comparisons
        new_res = json.loads(raw_sorted_json_text)
    else:
        # Handling string pulled from existing object that's already been processed
        raw.pop('misphunter_processed')
        raw_sorted_json_text = json.dumps(raw)
        checksum = md5_data(raw_sorted_json_text)
        new_res = json.loads(raw_sorted_json_text)
    
    # Get the best JSON blob to compare it to. e.g. censys-json cannot be compared to shodan-json
    json_type = f"{service}-json"
    json_attrs = misphandler.get_all_attrs_by_rel(host_obj, json_type)
    for attr in json_attrs:
        # Check checksum against the json filename (which contains the checksum)
        if attr.value.startswith(checksum):
            _log.info(f"Checksum {checksum} already saved to host_obj. Updating timestamp of JSON object.")
            # Update the timestamps to indicate we've seen this again
            misphandler.update_timestamps(attr)
            if not misphunter.force_ioc_extract:
                _log.debug(f"force_ioc_extract set to False. Returning object without processing new IOCs.")
            else:
                _log.info(f"force_ioc_extract set to True. Extracting IOCs from JSON blob {checksum}!")
                host_obj = force_ioc_extract(misphunter, checksum, host_obj, service, new_res)
            return host_obj
    
    # If you've made it this far, this host_obj already exists, but this json blob is new
    # Get the latest json blob to compare the new one to. Returns False if nothing for comparison.
    last_json_name, json_dict = get_latest_json(host_obj, checksum, json_type)

    if json_dict == False:
        _log.info(f"Could not find JSON blob to do comparison. "\
            f"Probably adding the first JSON blob of type {json_type} to host_obj {host_obj.uuid} - {host_ip}.")
        comment = f"First JSON blob of type {json_type} seen for this host."
        # Add the new blob...
        host_obj = misphandler.add_json_attr(checksum, raw_sorted_json_text, host_obj, json_type, comment=comment)
        # ...extract the IOCs
        host_obj = force_ioc_extract(misphunter, checksum, host_obj, service, new_res)
        # ...and return the host object
        return host_obj

    # If you're still running, we found two json blobs to compare
    _log.info(f"Comparing {checksum}.json and {last_json_name}...")
    compare_notes = dict_compare(json_dict, new_res)

    # Add new JSON blob to existing host object with dict comparison as the comment
    comment = f"Compared to {last_json_name}\n"
    comment += compare_notes
    host_obj = misphandler.add_json_attr(checksum, raw_sorted_json_text, host_obj, json_type, comment=comment)

    # Extract IOCs
    host_obj = force_ioc_extract(misphunter, checksum, host_obj, service, new_res)

    return host_obj

def flatten_data(misphunter, raw):
    _log.debug(f"Flattening JSON dictionary & removing hashes")
    try:
        sorted_json = flatten_dict(raw)
        _log.debug(f"JSON flattened.")
        _log.debug(f"{sorted_json}")
    except Exception as e:
        _log.error(f"FATAL (for now) Error sorting JSON - {e}")
        raise
    return sorted_json

def flatten_dict(dictionary, remove_dates=False, remove_hashes=False):
    """Flatten a nested json file"""

    def unpack(parent_key, parent_value):
        """Unpack one level of nesting in json file"""
        # Unpack one level only!!!
        # _log.debug(f"Unpacking parent_key: {parent_key} and parent_value: {str(parent_value)[0:35]}")
        if isinstance(parent_value, dict):
            for key, value in parent_value.items():
                temp1 = parent_key + '_' + key
                yield temp1, value
        elif isinstance(parent_value, list):
            i = 0 
            # NMD Handle Empty Lists
            if len(parent_value) <= 0:
                _log.debug(f"parent_value is list of length 0... which is an odd outlier")
                _log.debug(f"Doing nothing for parent_key: {parent_key}")
                # yield parent_key, []

            # NMD second attempt to fix this crap
            elif isinstance(parent_value[0], dict):
                '''
                # NMD third attempt to fix this crap
                # This try/except is redundant because eventually it'll do it a second time
                #   after sorting anyway...
                try:
                    for value in parent_value:
                        temp2 = parent_key + '_'+str(i) 
                        i += 1
                        yield temp2, value
                except Exception as e :
                    _log.error(f"Fucked again. temp {temp2} value {str(value)[0:25]}")
                    raise(e)
                '''
                _log.debug(f"first item in parent_value list is a dict, so we can't sort it...")
                _log.debug(f"NOT sorting parent_value...")
                '''

                # TODO Something is severely wrong in... all of this.
                # ...or maybe in how I was doing it originally? It seems to be... working?

                _log.debug(f"parent_value[0] {str(parent_value[0])[0:35]} is a dict.")
                _log.debug(f"There are {len(parent_value)} TOTAL parent_values.")
                if len(parent_value)>1:
                    _log.debug(f"parent_value[1] is {str(parent_value[1])[0:35]}")
                # list_of_keys = list(parent_value[0].keys())
                # ^^ isn't good enough because sometimes each parent_value has diff keys
                list_of_keys = []
                all_pv_types = {}
                for pv in parent_value:
                    pv_type = str(type(pv))
                    if pv_type not in all_pv_types:
                        all_pv_types[pv_type] = 1
                    else:
                        all_pv_types[pv_type]+=1
                    lk = list(pv.keys())
                    for k in lk:
                        if k not in list_of_keys:
                            list_of_keys.append(k)
                list_of_keys.sort()
                _log.debug(f"Breakdown of parent_value types: {all_pv_types}")

                # sorting_key = list_of_keys[0]
                # ^^ Isn't good enough because if the sorting_key isn't the same for all dicts
                #   it will fail.
                # loop through and check if sorting_keys are appropriate for parent_value dict.
                sorting_key=False
                for k in list_of_keys:
                    if sorting_key:
                        # we've got a key that appears in all dicts. Stop looking for more.
                        _log.debug(f"{k} appears in all parent_dicts! Sorting by that!")
                        break
                    for pv in parent_value:
                        if k not in pv:
                            # bad candidate for sorting_key
                            sorting_key = False
                            _log.debug(f"key {k} didn't appear in parent_dict")
                            break
                        else:
                            sorting_key = k
                
                try:
                    # parent_value.sort(key=lambda i:i[sorting_key])
                    parent_value.sort(key=lambda x:x[sorting_key])
                except Exception as e:
                    _log.error(f"SURPRISE! IT'S THIS FUCKING ERROR AGAIN! :)")
                    _log.error(f"I was TRYING to process parent_value {parent_value} with sorting_key {sorting_key}...\n"
                    f"...and whatever the fuck 'i' is supposed to be here {i}")
                    raise(f"{e}")
                for pv in parent_value:
                    pv = str(pv)
                '''
            else:
                try:
                    _log.debug(f"parent_value is not an empty list and parent_value[0] is not a dict.")
                    _log.debug(f"...sorting parent_value list...")
                    parent_value.sort()
                except Exception as e:
                    _log.error(f"FATAL (for now) Error trying to sort {parent_value}")
                    _log.error(f"{e}")
                    raise
            try:
                for value in parent_value:
                    temp2 = parent_key + '_'+str(i) 
                    i += 1
                    yield temp2, value
            except Exception as e :
                raise(e)
        else:
            if remove_dates:
                _log.debug(f"Removing Dates...")
                parent_value = sub_dates(parent_value)
            if remove_hashes:
                _log.debug(f"Removing hashes...")
                parent_value = sub_hashes(parent_value)
            yield parent_key, parent_value

    # Keep iterating until the termination condition is satisfied
    while True:
        # Keep unpacking the json file until all values are atomic elements (not dictionary or list)
        dictionary = dict(chain.from_iterable(starmap(unpack, dictionary.items())))
        # Terminate condition: not any value in the json file is dictionary or list
        if not any(isinstance(value, dict) for value in dictionary.values()) and \
           not any(isinstance(value, list) for value in dictionary.values()):
            break

    return dictionary

def force_ioc_extract(misphunter, checksum, host_obj, service, new_res):
    _log.info(f"Extracting IOCs...")
    # _log.debug(f"Before IOC extraction: ")
    # _log.debug(pformat(new_res))

    # Get dict of indicators we don't want to allow for IOC extraction
    cleanup = get_cleanup(service)

    # Get all the IOCs that can be hit by a generic regex on a blob of text
    iocs = get_iocs(misphunter, new_res, cleanup)

    # Add any  the certificate IOCs which are specific to a given service's results on a host.
    # if service == "censys-v1":
        # iocs = censys.censys_v1_extract_certs(iocs, new_res)
    if service == "censys-v2":
        iocs = censys.censys_v2_extract_certs(iocs, new_res)
    elif service == "shodan":
        iocs = shodan.shodan_extract_certs(iocs, new_res)
    else:
        _log.error(f"Unable to parse cert using service {service} - we weren't prepared for this!")

    if misphunter.debugging:
        _log.debug(f"#### All IOCs:")
        _log.debug(pformat(iocs))

    updated_obj = add_iocs_to_object(iocs, checksum, host_obj)

    '''
    _log.debug(f"Updating host_obj before leaving force_ioc_extract...")
    updated_obj = misphandler.update_existing_object(misphunter, updated_obj)

    if not updated_obj:
        _log.debug(f"THIS IS PROBABLY A BAD IDEA AND YOU SHOULD LOOK INTO WHY update_existing_object() FAILED!")
        _log.error(f"Something went wrong updating host object {host_obj.uuid}. Returning host_obj prior to update.")
        return host_obj
    '''

    return updated_obj

def get_latest_json(host_obj, checksum, json_type):
    _log.info(f"Getting last-saved JSON blob for comparison against {json_type} {checksum}.json.")
    latest_json = False
    json_attrs = misphandler.get_all_attrs_by_rel(host_obj, json_type)
    for attr in json_attrs:
        if attr.object_relation == json_type:
            if not latest_json:
                _log.debug(f"Grabbing first JSON blob for comparison: {attr.value}")
                latest_json = attr
            elif attr.last_seen > latest_json.last_seen:
                _log.debug(f"Found newer JSON blob for comparison: {attr.value}")
                latest_json = attr
            else:
                _log.debug(f"Found JSON blob {attr.value}, but its timestamp [{attr.timestamp}]"\
                    f"is older than the blob we've already grabbed [{latest_json.value} - {latest_json.timestamp}]")

    if not latest_json:
        _log.debug(f"We have a new blob with checksum {checksum} for an existing host, "\
            f"but we were unable to get a pre-existing JSON blob of the same type to compare "\
            f"it to. This will happen when adding the first JSON blob from a new service.")
        return False, False

    # If you've made it this far, you've got the latest JSON blob for comparison with your new blob
    blob = latest_json.data.read()
    _log.debug(f"blobg length: {len(blob)}")
    raw_json = blob.decode('utf-8')
    _log.debug(f"raw_json length: {raw_json}")
    # _log.debug(f"raw_json first 10 chars: {raw_json[0:10]}")
    json_dict = json.loads(raw_json)

    # Return the name of the latest_json blob and the parsed dictionary of its data
    return latest_json.value, json_dict

def get_cleanup(service):
    cleanup = {}

    if service=="censys-v1":
        cleanup = censys.censys_v1_cleanup_rules()
    elif service=="censys-v2":
        cleanup = censys.censys_v2_cleanup_rules()
    elif service=="shodan":
        cleanup = shodan.shodan_cleanup_rules()

    return cleanup

def get_iocs(misphunter, data, cleanup):
    # Does the gruntwork of pulling IOCs out via Regex from large blobs
    misp = misphunter.misp
    ips = []
    urls = []
    emails = []
    domains = []
    context = {}

    for k, v in data.items():
        if not isinstance(v, str):
            continue
        try:
            for ip in iocextract.extract_ipv4s(v, refang=True):
                if ip not in ips:
                    # if IP matches valid regex
                    ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", ip)
                    if ip_match:
                        ips.append(ip_match.group())
                        context[ip_match.group()] = k
                    else:
                        _log.debug(f"{ip} is not a valid IP format")
        except Exception as e:
            _log.error(f"Error processing value {v}: {e}")
        try:
            for url in iocextract.extract_urls(v, refang=True):
                if url not in urls:
                    url_match = re.search(r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})", url)
                    if url_match:
                        urls.append(url_match.group())
                        context[url_match.group()] = k
                    else:
                        _log.debug(f"{url} is not a valid URL format")
        except Exception as e:
            _log.error(f"Error processing value {v}: {e}")
        try:
            for email in iocextract.extract_emails(v, refang=True):
                if email not in emails:
                    email_match = re.search(r"([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})", email)
                    if email_match:
                        emails.append(email_match.group())
                        context[email_match.group()] = k
                    else:
                        _log.debug(f"{email} is not a valid email format")
        except Exception as e:
            _log.error(f"Error processing value {v}: {e}")
        # Get domains from URLs
        for url in urls:
            domain_match = re.search(r":\/\/(.*?)(/|$)", url)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in domains:
                    domains.append(domain)
                    context[domain] = k

    # clean junk domains
    if len(domains)>0:
        domains = clean_junk_domains(domains, context, cleanup, misp)
    
    # clean junk IPs
    if len(ips)>0:
        if 'ips' in cleanup.keys():
            ips = junk_iocs(ips, context, cleanup['ips'])

    # clean junk emails
    if len(emails)>0:
        if 'emails' in cleanup.keys():
            emails = junk_iocs(emails, context, cleanup['emails'])

    if len(urls)>0:
        if 'urls' in cleanup.keys():
            urls = junk_iocs(urls, context, cleanup['urls'])

    iocs = {
        'ips': ips,
        'urls': urls,
        'emails': emails,
        'domains': domains,
        'context': context
    }

    return iocs

def get_raw_json_text(sorted_json):
    raw_json = json.dumps(sorted_json)
    return raw_json

def junk_iocs(iocs, context, cleanup):
    _log.info(f"Cleaning up junk IOCs according to plugin cleanup keys "
        "and \"Top\" warning lists.")
    ioc_copy = iocs.copy()
    for ioc in ioc_copy:
        c = context[ioc]
        for s in cleanup['keys']['startswith']:
            if c.startswith(s):
                _log.debug(f"key {c} starts with {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['keys']['equals']:
            if c==s:
                _log.debug(f"key {c} equals {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['keys']['endswith']:
            if c.endswith(s):
                _log.debug(f"key {c} ends with {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['keys']['contains']:
            if s in c:
                _log.debug(f"key {c} contains {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['values']['startswith']:
            if ioc.startswith(s):
                _log.debug(f"value {ioc} starts with {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['values']['equals']:
            if ioc == s:
                _log.debug(f"value {ioc} equals {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['values']['endswith']:
            if ioc.endswith(s):
                _log.debug(f"value {ioc} ends with {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
        for s in cleanup['values']['contains']:
            if s in ioc:
                _log.debug(f"value {ioc} contains {s}. Removing {ioc} from final list.")
                iocs.remove(ioc)
    return iocs

def md5_data(data):
    flat = str(data)
    _log.debug(f"Calculating hash of clean JSON blob with length {len(flat)}")
    r = hashlib.md5(flat.encode())
    checksum = r.hexdigest()
    _log.info(f"Calculated checksum of {checksum}")
    return checksum

def organize_event_objects(event):

    rel_index = {
        'all_hosts': {},
        'all_certs': {}
    }
    # _log.debug(f"#### ORGANIZING RELATIONSHIP INDEX ####")
    # Organize event objects
    for obj in event.Object:
        if hasattr(obj, 'ObjectReference'):
            for ref in obj.ObjectReference:
                if ref.relationship_type not in rel_index:
                    rel_index[ref.relationship_type] = {obj.uuid : [ref.referenced_uuid]}
                elif obj.uuid not in rel_index[ref.relationship_type]:
                    rel_index[ref.relationship_type][obj.uuid] = [ref.referenced_uuid]
                else:
                    rel_index[ref.relationship_type][obj.uuid].append(ref.referenced_uuid)

        if obj.name=="misphunter-host":
            ip = misphandler.get_attr_val_by_rel(obj, 'host-ip')
            if not ip:
                _log.error(f"host-ip attribute not found in misphunter-host obj {obj.uuid}. Skipping!")
                continue
            if ip not in rel_index['all_hosts']:
                rel_index['all_hosts'][ip] = obj.uuid
        if obj.name == "misphunter-cert":
            cert = misphandler.get_attr_val_by_rel(obj, 'cert-sha256')
            if not cert:
                _log.error(f"cert-sha256 attribute not found in misphunter-cert obj {obj.uuid}. Skipping!")
                continue
            if cert not in rel_index['all_certs']:
                rel_index['all_certs'][cert] = obj.uuid
            
    # _log.debug(f"#### RELATIONSHIP INDEX ORGANIZED ####")
    # _log.debug(f"\n\nrel_index:\n\n")
    # _log.debug(f"{pformat(rel_index)}")
    return rel_index

def parse_cert(cert_fingerprint_pattern, cert_name_pattern, iocs, new_res):
    _log.info(f"Parsing certificate for fingerprint hashes and potential domains...")
    for k, v in new_res.items():
        cert_fingerprint = False
        cert_fingerprint = re.search(cert_fingerprint_pattern, k)
        if cert_fingerprint:
            if 'certificates' not in iocs:
                iocs['certificates'] = [v]
                if 'context' not in iocs:
                    iocs['context'] = {v:k}
                else:
                    iocs['context'][v] = k
            if v not in iocs['certificates']:
                iocs['certificates'].append(v)
                iocs['context'][v] = k

        cert_name = False
        cert_name = re.search(cert_name_pattern, k)
        if cert_name:
            _log.debug(f"FOUND CERT NAME! {v}")
            domain_match = re.search(r"([A-Za-z0-9\-\.]+\.[A-Za-z]{2,})", v)
            if domain_match:
                domain = domain_match.group(1)
                if 'domains' not in iocs:
                    iocs['domains'] = [domain]
                    if 'context' not in iocs:
                        iocs['context'] = {domain:k}
                    else:
                        iocs['context'][domain] = k
                if domain not in iocs['domains']:
                    iocs['domains'].append(domain)
                    iocs['context'][domain] = k

    return iocs

def rate_respect(search_time, wait_sec):
    from time import time, sleep
    i = False
    while i == False:
        now = time()
        time_left = wait_sec - (now-search_time)
        if time_left <= 0:
            _log.info(f"{wait_sec}-second-per call time limit reached. Moving on!")
            i = True
            return search_time
        else:
            _log.info(f"HOL UP! You need to respect the rate limit by waiting {int(time_left)} more seconds!")
            sleep(int(time_left))
            _log.info(f"{wait_sec}-second-per call time limit reached. Moving on!")
            i = True
            return search_time

def remove_dates(misphunter, raw_sorted_json_text):
    checksum = md5_data(raw_sorted_json_text)
    stime = int(time())
    if misphunter.debugging:
        _log.debug(f"Selected to scrub dates from data. Before data:")
        _log.debug(f"Before checksum: {checksum}")
    
    raw_sorted_copy = raw_sorted_json_text.copy()
    for k, v in raw_sorted_copy.items():
        v = sub_dates(v)
        raw_sorted_json_text[k] = v
        
    runtime=int(time())-stime
    
    checksum = md5_data(raw_sorted_json_text)
    if misphunter.debugging:
        _log.debug(f"After scrub (runtime: {runtime} seconds):")
        _log.debug(f"After checksum: {checksum}")

    return raw_sorted_json_text

def run_host_seed(misphunter, search, service):
    # This is used to process a misphunter-seed that searches for hosts. It should return a plain list of IPs.
    ips = []
    if service=='censys-v1':
        # ips = censys.censys_v1_search(misphunter, search)
        return ips
    elif service=='censys-v2':
        ips = censys.censys_v2_search(misphunter, search, per_page=100)
    elif service=='shodan':
        ips = shodan.shodan_search(misphunter, search)
    else:
        _log.error(f"No search function found for service type {service}...")
    return ips

def search_cert_data(misphunter, cert_hash, host_obj, event):
    # returns MISPObject with all the data you could possibly want for a specific certificate

    _log.info(f"Getting all certificate data for {cert_hash}...")
    cert_data = False
    
    # Run these in order of priority. The idea is that if you have a cert from one service
    #   you probably have a cert from all services. So once you get one, no need to search
    #   the others.
    #   Also of note, at the moment, censys-v1 is the only censys option.
    if misphunter.censys_v1_active:
        cert_data = censys.censys_v1_search_cert_data(misphunter, cert_hash, event)
        if 'error_type' in cert_data:
            _log.error(f"Received error from Censys instead of certificate data: {cert_data['error']}")
            return False
        if cert_data:
            _log.debug(f"Results found when running search_cert_data for cert_hash {cert_hash}")

            # If the result was an existing MISPObject, great - let's use that going forward!
            if isinstance(cert_data, MISPObject):
                _log.debug(f"Returned existing MISPObject [{cert_data.uuid}] when searching for cert.")
                # cert_data came back as an already-built MISP object. Nothing else we need to do.
                if not hasattr(cert_data, 'is_new'):
                    _log.debug(f"is_new not set for cert_data, meaning we pulled it straight from the MISP instance. Setting it to False.")
                    cert_data.is_new = False
                # Add host_obj IP to cert_obj if doesn't exist
                cert_obj_ips = []
                cert_ip_attrs = cert_data.get_attributes_by_relation('cert-ip')
                for attr in cert_ip_attrs:
                    if attr.value not in cert_obj_ips:
                        cert_obj_ips.append(attr.value)

                host_ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
                if host_ip:
                    if host_ip not in cert_obj_ips:
                        _log.debug(f"{host_ip} not found in set of IPs already belonging to misphunter-cert object. Adding!")
                        cert_data.add_attribute('cert-ip', host_ip, type="ip-dst", disable_correlation=False, to_ids=False, pythonify=True)
                else:
                    _log.error(f"ERROR - No host-ip associated with [{host_obj.uuid}]")
                    return cert_data 

                # Update timestamps
                for attr in cert_data.Attribute:
                    misphandler.update_timestamps(attr)

                return cert_data

            # Otherwise, cert_data came back as a raw response from Censys
            new_cert_obj = misphandler.build_misphunter_cert(misphunter, cert_hash, host_obj, event, cert_data)
            return new_cert_obj
        else:
            _log.warning(f"Something went wrong. Got no search results for cert {cert_hash}.")
            return False
    
def search_cert_hosts(misphunter, cert_data, host_ip):
    # Searches services for hosts associated with a given certificate
    # Updates the misphunter-cert object with any new IPs that were found
    # Returns the misphunter-cert object as well as a plain list of IPs found by searching the certificate
    
    all_ips = []
    ips = {}

    cert_hash = misphandler.get_attr_val_by_rel(cert_data, 'cert-sha256')
    _log.info(f"Searching for additional IPs associated with cert {cert_hash}")

    if misphunter.censys_v2_active:
        _log.debug(f"checking censys for IPs associated with {cert_hash}...")
        censys_v2_ips = censys.censys_v2_search_cert_hosts(misphunter, cert_hash)

        # Avoid getting caught in a loop by keeping this host we're currently processing
        # out of the mix
        if host_ip in censys_v2_ips:
            censys_v2_ips.remove(host_ip)

        if len(censys_v2_ips) > misphunter.cert_pivot_threshold:
            _log.warning(f"Censys returned {len(censys_v2_ips)}, which is higher than the threshold "
                f"set of {misphunter.cert_pivot_threshold}. Truncating results.")
        censys_v2_ips = censys_v2_ips[0:misphunter.cert_pivot_threshold]

        _log.info(f"Censys IPs found: {censys_v2_ips}")
        
        ips['censys-v2'] = censys_v2_ips
        for ip in censys_v2_ips:
            if ip not in all_ips:
                all_ips.append(ip)
    else:
        _log.info(f"censys-v2 not listed as active. Skipping!")

    if misphunter.shodan_active:
        _log.debug(f"checking shodan for IPs associated with {cert_hash}...")
        shodan_ips = shodan.shodan_search_cert_hosts(misphunter, cert_hash)

        # Avoid getting caught in a loop by keeping this host we're currently processing
        # out of the mix
        if host_ip in shodan_ips:
            shodan_ips.remove(host_ip)

        if len(shodan_ips) > misphunter.cert_pivot_threshold:
            _log.warning(f"Shodan returned {len(shodan_ips)}, which is higher than the threshold "
                f"set of {misphunter.cert_pivot_threshold}. Truncating results.")
        shodan_ips = shodan_ips[0:misphunter.cert_pivot_threshold]

        _log.info(f"Shodan IPs found: {shodan_ips}")

        ips['shodan'] = shodan_ips
        for ip in shodan_ips:
            if ip not in all_ips:
                all_ips.append(ip)
    else:
        _log.info(f"shodan not listed as active. Skipping!")

    # add IPs to cert_data object
    cert_data = misphandler.add_ips_to_cert_obj(cert_data, ips)

    return cert_data
    
def search_ip(misphunter, event, seed, host_obj):

    service = misphandler.get_attr_val_by_rel(seed, 'service')

    if service == "censys-v1":
        _log.debug(f"Running censys-v1 search")
        # raw = censys.censys_v1_search_ip(misphunter, event, seed, host_ip)
        raw = []
    elif service == 'censys-v2':
        _log.debug(f"Running censys-v2 search")
        raw = censys.censys_v2_search_ip(misphunter, event, seed, host_obj)
    elif service == 'shodan':
        _log.debug(f"Running shodan search")
        # raw = shodan.shodan_search_ip(misphunter, host_ip, service)
        raw = shodan.shodan_search_ip(misphunter, event, seed, host_obj)
    else:
        _log.debug(f"Hunt type {service} not found - are you sure that's a valid module?")
    
    return raw

def set_type(v, vtype):    
    if vtype == "str":
        if not isinstance(v, string_types):
            if isinstance(v, bytes):
                return v.decode("utf-8")
            return str(v)
    elif vtype == "bytes":
        if not isinstance(v, bytes):
            v = set_type(v, "str")
            return v.encode("utf-8")
    elif vtype == "int":
        if re.search("bool", set_type(type(v), "str")):
            if v == True:
                return 1
            return 0
        elif v in ["True", "true"]:
            return 1
        elif v in ["False", "false"]:
            return 0
        elif isinstance(v, string_types):
            try:
                return int(v)
            except:
                return 0
    # elif vtype == "timestamp":
    #     return to_datetime(v)
    elif vtype == "datetime":
        return datetime.fromtimestamp(v)
    elif vtype == "ip":
        return str(ipaddress.ip_address(v))
    elif vtype == "ip_object":
        return ipaddress.ip_address(v)
    elif vtype == "cidr":
        return str(ipaddress.ip_network(v))
    elif vtype == "cidr_object":
        return ipaddress.ip_network(v)
    
    # elif vtype == "ip_range_summary":
    #     first, last = v.split("-")
    #     first = ipaddress.ip_address(clean(first, normalize=True))
    #     last = ipaddress.ip_address(clean(last, normalize=True))
    #     cidrs = [ipaddr for ipaddr in ipaddress.\
    #         summarize_address_range(first, last)]
    #     return str(cidrs[0])
    
    elif vtype == "ip_compress":
        as_ips = [ipaddress.ip_network(_v) for _v in v]
        collapsed = [ipaddr for ipaddr in ipaddress.collapse_addresses(as_ips)]
        return str(collapsed[0])
    elif vtype == "ip_is_global":
        if ipaddress.ip_address(set_type(v, "ip")).is_global:
            return v
        return False
    elif vtype == "ymd":
        v = set_type(v, "timestamp")
        return datetime.strftime(v, "%Y-%m-%d")
    elif vtype == "ymdh":
        v = set_type(v, "timestamp")
        return datetime.strftime(v, "%Y%m%d%H")
    elif vtype == "string_datetime":
        v = set_type(v, "timestamp")
        return datetime.strftime(v, "%Y-%m-%dT%H:%M:%S")
    return v

def sort_json(unsorted_json):
    sorted_json = OrderedDict(sorted(unsorted_json.items()))
    return sorted_json

def sort_raw_json(misphunter, raw, hunt):
    flat_unsorted_json = flatten_data(misphunter, raw)    
    unsorted_json = clean_keys(misphunter, flat_unsorted_json, hunt)
    # _log.debug(f"\n\nAfter running helper.clean_keys, unsorted_json:\n\n{unsorted_json}\n\n")
    unsorted_json_key_swap = swap_json_keys(unsorted_json)
    sorted_json = sort_json(unsorted_json_key_swap)
    # _log.debug(f"\n\nsorted_json:\n\n{sorted_json}\n\n")
    
    raw_sorted_json_text = get_raw_json_text(sorted_json)
    _log.debug(f"\n\nraw_sorted_json_text:\n\n{raw_sorted_json_text}\n\n")
    return raw_sorted_json_text

def sub_hashes(s, do_remove=True):
    if not do_remove:
        return s
    try:
        s = re.sub("[a-f0-9]{32|40|64}", "", s.lower())
    except:
        pass
    try:
        #shodan hashes appear to be 9 - 10 signed integers
        s = re.sub("\-?[0-9]{9,10}", "", set_type(s, "str").lower())
    except:
        pass
    return s

def sub_dates(s, do_remove=True):
    if not do_remove:
        return s
    try:
        if set_type(s, "cidr"):
            return s
    except:
        pass
    try:
        results = search_dates(s)
        to_sub = [res for res in results if res[0].lower() != "today"]
        for ts in to_sub:
            s = re.sub(ts[0], " ", s) 
    except Exception as err:
        pass
    try:
        s = re.sub("([0-9]{1,2}(:|\-){0,1}){2}[0-9]{0,2}[a-zA-Z]{0,2}", "", s)
    except Exception as err:
        pass
    return s

def swap_json_keys(unsorted_json):
    # replace things like services_0_port and data_0_port with 80_port
    _log.debug(f"Swapping generic keys with port numbers...")
    swap_keys = {}
    for k, v in unsorted_json.items():
        if k.endswith("_port"):
            # _log.debug(f"Found key ending in _port: {k}. Has value of {v}")
            key_port = str(v)
            swap_key_match = re.match(r"^(.*?)_port$", k)
            swap_key = str(swap_key_match[1])
            # _log.debug(f"swap_key value is: {swap_key}")
            if swap_key not in swap_keys:
                swap_keys[swap_key] = key_port

    # _log.debug(f"Keys to swap out: ")
    # _log.debug(f"{pformat(swap_keys)}")

    new_dict = {}

    for k, v in unsorted_json.items():
        for swap_key, key_port in swap_keys.items():
            if swap_key in k:
                # _log.debug(f"Replacing swap_key {swap_key} with key_port {key_port}...")
                new_k = k.replace(swap_key, key_port)
                new_dict[new_k] = v

    return new_dict

def track_stats_tags_added(misphunter, tag, attr):
    if tag not in misphunter.run_stats['tags_added']:
        misphunter.run_stats['tags_added'][tag] = [attr.uuid]
    elif attr.uuid not in misphunter.run_stats['tags_added'][tag]:
        misphunter.run_stats['tags_added'][tag].append(attr.uuid)
    misphunter.run_stats['tags_added']['total'] += 1

def track_stats_tags_removed(misphunter, tag, attr):
    if tag not in misphunter.run_stats['tags_removed']:
        misphunter.run_stats['tags_removed'][tag] = [attr.uuid]
    elif attr.uuid not in misphunter.run_stats['tags_removed'][tag]:
        misphunter.run_stats['tags_removed'][tag].append(attr.uuid)
    misphunter.run_stats['tags_removed']['total'] += 1
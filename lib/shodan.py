import json
import logging, logging.handlers, sys

from time import time

import shodan
from shodan import Shodan

from . import helper, misphandler

def shodan_cleanup_rules():
    # IOCs with these types of keys and values will be ignored from being created
    # e.g. IP 192.168.1.1 is extracted from autonomous_system_value key
    # ips['keys']['startswith']['autonomous_system'] will cause it to be scrubbed
    # ips['values']['endswith']['2.2.2', '168.1.1'] will cause it to be scrubbed
    cleanup_rules = {
        'ips': {
            'keys' : {
                'startswith': ['autonomous_system'],
                'endswith': ['source_ip'],
                'equals': [],
                'contains': []
            },
            'values': {
                'startswith': [],
                'endswith': [],
                'equals': [],
                'contains': []
            }
            
        },
        'emails':{
            'keys': {
                'startswith': [],
                'endswith': [],
                'equals': [],
                'contains': []
            },
            'values': {
                'startswith': [],
                'endswith': ['@openssh.com', '@libssh.org'],
                'equals': ['rijndael-cbc@lysator.liu.se', 'rijndael-cbc@lysator.liu'],
                'contains': []
            }
        },
        'domains':{
            'keys': {
                'startswith': [],
                'endswith': [],
                'equals': [],
                'contains': []
            },
            'values': {
                'startswith': [],
                'endswith': ['censys.io', 'w3.org'],
                'equals': [],
                'contains': []
            }
        },
        'urls':{
            'keys': {
                'startswith': [],
                'endswith': [],
                'equals': [],
                'contains': []
            },
            'values': {
                'startswith': [],
                'endswith': ['censys.io/'],
                'equals': [],
                'contains': []
            }
        }
    }

    return cleanup_rules

def shodan_clean_json_keys():
    # This adds a set of keywords to remove for clean comparison of changes
    # across time. e.g. when taking the hash of two blobs of censys data, the
    # hash would change if they both had different time_scraped values. So we
    # want to remove those before the comparison.
    # Looks for keys that END WITH the follow values
    
    ignored_keys = {
        "startswith": [],
        "endswith": [
            "timestamp",
            "_shodan",
            "last_update",
            "_id",
            "_asn",
            "_isp"
        ],
        "equals": [],
        "contains": [
            "_shodan_",
            "_opts_",
            "_location_"
        ]
    }

    return ignored_keys


def shodan_search(mh, search):
    mh.logger.debug(f"Running SHODAN search {search}")
    raw = {}
    ips = []
    shodan_api = Shodan(mh.shodan_key)

    if mh.do_it_live:
        mh.logger.debug(f"Using LIVE API query to search SHODAN...")
        # Get rate_limit for this service
        rate_limit = mh.shodan_rate
        try:
            
            # Sleep {rate_limit} seconds for each time the search is run
            helper.rate_respect(mh, mh.search_time, rate_limit)
            mh.search_time = time()
            raw = shodan_api.search(query=f"{search}")
            mh.shodan_api_counter+=1
            mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
            mh.logger.debug(f"SHODAN got a 200 OK for {search}!")

        except shodan.APIError:
            mh.logger.error(f"Error - API timed out. Trying again...")
            try:
                helper.rate_respect(mh, mh.search_time, rate_limit+1)
                mh.search_time = time()
                raw = shodan_api.search(query=f"{search}")
                mh.shodan_api_counter+=1
                mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
                mh.logger.debug(f"SHODAN got a 200 OK for {search}!")

            except Exception as e:
                mh.logger.error(f"Error searching SHODAN for query {search}: {e}")
                # raise Exception(e)
                return ips

        except Exception as e:
            mh.logger.error(f"Error searching SHODAN for query {search}: {e}")
            # raise Exception(e)
            return ips

    else:
        # DEBUGGER - DUMMY DATA
        mh.logger.debug(f"do_it_live==False - using dummy data")
        raw = {'matches': [{'ip': 123456789, 'product': 'nginx', 'total': 1}]}
    
    
    # for r in parse_res['results']:
    if 'matches' in raw:
        for match in raw['matches']:
            if 'ip_str' in match:
                if match['ip_str'] not in ips:
                    ips.append(match['ip_str'])

    return ips

def shodan_search_ip(mh, host_obj):
    ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
    service = "shodan"

    mh.logger.debug(f"Getting raw JSON data for {ip}")
    raw = {}
    shodan_api = Shodan(mh.shodan_key)

    if not mh.do_it_live:
        ### FOR DEBUGGING
        mh.logger.debug(f"do_it_live==False - using dummy data")
        raw = {'region_code': '16', 'tags': ['cloud'], 'ip': 1234567890, 'area_code': None, 'domains': ['linode.com'], 'postal_code': None, 'dma_code': None, 'org': 'Linode, LLC', 'ip_str': '192.168.1.100'}
        return raw

    # Get rate_limit for this service
    rate_limit = mh.shodan_rate
    fresh_json = misphandler.check_json_freshness(mh, host_obj, service)
    if fresh_json:
        return fresh_json
    
    mh.logger.debug(f"Discovered no fresh JSON blobs that are appropriate for reuse.")
    mh.logger.debug(f"Using LIVE API query to reach out to Shodan and get IP data...")

    try: 
        # Sleep {rate_limit} seconds for each time the search is run
        helper.rate_respect(mh, mh.search_time, rate_limit)
        mh.search_time = time() 
        raw = shodan_api.host(ip)
        mh.shodan_api_counter+=1
        mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
        # raw = json.loads(res)
        if mh.debugging:
            mh.logger.debug(f"Results for {ip}: \n\n{raw}")
        
    except shodan.APIError:
        mh.logger.error(f"Error - API timed out. Trying again...")
        try:
            helper.rate_respect(mh, mh.search_time, rate_limit+1)
            mh.search_time = time()
            raw = shodan_api.host(ip)
            mh.shodan_api_counter+=1
            mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
            # raw = json.loads(res)
            if mh.debugging:
                mh.logger.debug(f"Results for {ip}: \n\n{raw}")

        except Exception as e:
            mh.logger.error(f"Error getting IP {ip}: {e}")
            # raw = {"error": "IP Not Found"}
            return False

    '''
    except Exception as e:
        mh.logger.error(f"Error getting IP {ip}: {e}")
        # raw = {"error": "IP Not Found"}
        return False
    '''
    
    return raw
    
def shodan_search_cert_hosts(mh, cert):
    # hunt_type = 'censys-v2'
    mh.logger.debug(f"Getting raw JSON data from SHODAN for {cert}")
    raw = {}
    ips = []
    shodan_api = Shodan(mh.shodan_key)
    
    if mh.do_it_live:
        
        mh.logger.info(f"Using LIVE API query to reach out to SHODAN and find hosts associated with cert {cert}...")
        # Sleep {rate_limit} seconds for each time the search is run
        rate_limit = mh.shodan_rate
        try:
            # rate_limit = helper.get_rate_limit(mh, 'censys')
            helper.rate_respect(mh, mh.search_time, rate_limit)
            mh.search_time = time() 
            # raw = shodan_api.search(query=f"ssl.cert.fingerprint:\"{cert}\"")
            # ^^ only works with SHA1 and I'm trying to keep it uniform.
            raw = shodan_api.search(query=f"ssl:\"{cert}\"")
            mh.shodan_api_counter+=1
            mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
            mh.logger.debug(f"SHODAN got a 200 OK for {cert}!")

        except shodan.APIError:
            mh.logger.error(f"Error - API timed out. Trying again...")
            try:
                helper.rate_respect(mh, mh.search_time, rate_limit+1)
                mh.search_time = time()
                raw = shodan_api.search(query=f"ssl:\"{cert}\"")
                mh.shodan_api_counter+=1
                mh.logger.debug(f"\n\n#### TOTAL SHODAN API CALLS NOW {mh.shodan_api_counter}! \n\n")
                mh.logger.debug(f"SHODAN got a 200 OK for {cert}!")

            except Exception as e:
                mh.logger.error(f"Error searching SHODAN for certificate {cert}: {e}")
                return ips

        except Exception as e:
            mh.logger.error(f"Error searching SHODAN for certificate {cert}: {e}")
            return ips
    
    #### FOR DEBUGGING
    else:
        mh.logger.debug(f"do_it_live==False - using dummy data")
        raw = {'matches': [{'ip': 123456789, 'product': 'nginx', 'total': 1}]}

    if 'matches' in raw:
        for match in raw['matches']:
            if 'ip_str' in match:
                ips.append(match['ip_str'])

    return ips

def shodan_extract_certs(mh, iocs, new_res):
    mh.logger.debug(f"Extracting certificate IOCs from Shodan data...")
    cert_fingerprint_pattern = r"(\d+_ssl_cert_fingerprint_sha256)"
    cert_name_pattern = r"\d+_ssl_cert_subject_CN"

    iocs = helper.parse_cert(mh, cert_fingerprint_pattern, cert_name_pattern, iocs, new_res)
    return iocs
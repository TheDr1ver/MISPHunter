import json
import logging, logging.handlers, sys
import requests

from time import time

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

def censys_v1_search_cert_data(misphunter, cert, event):
    # Return MISPObject of cert_data if already found, otherwise return raw censys response
    cert_data = False
    _log.info(f"Getting raw JSON data for {cert}")
    raw = {}
    url = f"https://search.censys.io/api/v1/view/certificates/{cert}"
    auth = (misphunter.censys_v1_id, misphunter.censys_v1_secret)
    headers = {"accept": "application/json"}

    if misphunter.do_it_live:
        cert_data = misphandler.check_all_certs(misphunter, cert, event)
        if cert_data:
            # if check_all_certs returns a misphunter-cert object, we're using an existing (and the latest) MISPObject
            return cert_data

        # If cert_data == False, we didn't find a cert_object and we need to create one.
        _log.info(f"Using LIVE API query to reach out to Censys and get certificate data...")
        try:
            rate_limit = misphunter.censys_v1_rate
            # Sleep {rate_limit} seconds for each time the search is run
            helper.rate_respect(misphunter.search_time, rate_limit)
            misphunter.search_time = time() 
            res = requests.get(url, auth=auth)
            misphunter.censys_v2_api_counter+=1
            _log.debug(f"\n\n#### TOTAL CENSYS API CALLS NOW {misphunter.censys_v2_api_counter}! \n\n")
            if res.status_code == 200:
                raw = json.loads(res.text)
                if misphunter.debugging:
                    _log.debug(f"Results for {cert}: \n\n{raw}")
            else:
                _log.error(f"Error getting cert {cert}. Status: {res.status_code} - {res}")
                return raw
        except Exception as e:
            _log.error(f"Error getting cert {cert}: {e}")
            return raw

    #### FOR DEBUGGING
    else:
        _log.info(f"do_it_live==False, using dummy data")
        raw = {"fill_this": "with whatever dummy cert data you want to pull from the certificates endpoint."}

    return raw

def censys_v1_clean_json_keys():
    # This adds a set of keywords to ignore for clean comparison of changes
    # across time. e.g. when taking the hash of two blobs of censys data, the
    # hash would change if they both had different time_scraped values. So we
    # want to remove those before the comparison.
    ignored_keys = [
        "updated_at",
        "observed_at",
        "perspective_id"
    ]

    return ignored_keys

def censys_v2_cleanup_rules():
    # IOCs with these types of keys and values will be ignored from being created
    # e.g. IP 192.168.1.1 is extracted from autonomous_system_value key
    # ips['keys']['startswith']['autonomous_system'] will cause it to be scrubbed
    # ips['values']['endswith']['2.2.2', '168.1.1'] will cause it to be scrubbed
    cleanup_rules = {
        'ips': {
            'keys' : {
                'startswith': ['autonomous_system'],
                'endswith': ['source_ip', 'perspective_id'],
                'equals': ['ip'],
                'contains': ['algorithm']
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
                'endswith': ['censys.io'],
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

def censys_v2_clean_json_keys():
    # This adds a set of keywords to ignore for clean comparison of changes
    # across time. e.g. when taking the hash of two blobs of censys data, the
    # hash would change if they both had different time_scraped values. So we
    # want to remove those before the comparison.
    ignored_keys = [
        "updated_at",
        "observed_at",
        "perspective_id",
        "source_ip"
    ]

    return ignored_keys

def censys_v2_extract_certs(iocs, new_res):
    # extracts certificates from the raw JSON response 
    # and adds them to the list of IOCS

    # Find the key containing the cert hash
    cert_fingerprint_pattern = r"(services_\d+_certificate)"
    # Find the key containing server names associated with the cert
    cert_name_pattern = r"leaf_data_names"

    iocs = helper.parse_cert(cert_fingerprint_pattern, cert_name_pattern, iocs, new_res)
    return iocs

def censys_v2_search(misphunter, search, per_page=100):
    # run the search and return all resulting IPs
    _log.info(f"Running Censys v2 search {search}")
        
    ips = []
    url = "https://search.censys.io/api/v2/hosts/search"
    auth = (misphunter.censys_v2_id, misphunter.censys_v2_secret)
    params = {
        "q": search,
        "per_page": per_page
    }
    
    if misphunter.do_it_live:
        _log.info(f"Using LIVE API query to search censys...")
        try:
            # Get rate_limit for this service
            rate_limit = misphunter.censys_v2_rate

            # Sleep {rate_limit} seconds for each time the search is run
            helper.rate_respect(misphunter.search_time, rate_limit)

            misphunter.search_time = time()

            res = requests.get(url, auth=auth, params=params)

            misphunter.censys_v2_api_counter+=1
            _log.debug(f"\n\n#### TOTAL CENSYS API CALLS NOW {misphunter.censys_v2_api_counter}! \n\n")

            if res.status_code == 200:
                parse_res = json.loads(res.text)
            else:
                _log.error(f"Error searching query {search} status: {res.status_code} - {res.text}")
                return ips

        except Exception as e:
            _log.error(f"Error searching query {search}: {e}")
            return ips

        if misphunter.debugging:
            _log.debug(f"Search results:\n\n")
            _log.debug(f"{parse_res}")
    else:
        # DEBUGGER - DUMMY DATA
        _log.info(f"do_it_live=False, using dummy data")
        parse_res = {"fill_with": "dummy_data"}

    r = parse_res['result']
    if r['total']>0:
        for hit in r['hits']:
            if hit['ip'] not in ips:
                ips.append(hit['ip'])

    _log.info(f"Found {len(ips)} IPs: {ips}")
    return ips

def censys_v2_search_cert_hosts(misphunter, cert):
    _log.info(f"Getting raw JSON data for {cert} from Censys")
    raw = {}
    ips = []
    url = f"https://search.censys.io/api/v2/certificates/{cert}/hosts"
    auth = (misphunter.censys_v2_id, misphunter.censys_v2_secret)
    headers = {"accept": "application/json"}
    
    if misphunter.do_it_live:
        _log.info(f"Using LIVE API query to reach out to Censys and find hosts associated with certificate...")
        try:
            rate_limit = misphunter.censys_v2_rate
            # Sleep {rate_limit} seconds for each time the search is run
            helper.rate_respect(misphunter.search_time, rate_limit)
            misphunter.search_time = time() 

            res = requests.get(url, headers=headers, auth=auth)

            misphunter.censys_v2_api_counter+=1
            _log.debug(f"\n\n#### TOTAL CENSYS API CALLS NOW {misphunter.censys_v2_api_counter}! \n\n")

            if res.status_code == 200:
                raw = json.loads(res.text)
                if misphunter.debugging:
                    _log.debug(f"Results for {cert}: \n\n{raw}")
            else:
                _log.error(f"Error getting certificate {cert}. Status: {res.status_code} - {res}")
                return ips
        except Exception as e:
            _log.error(f"Error getting certificate {cert}: {e}")
            return ips
    
    #### FOR DEBUGGING
    else:
        _log.info(f"do_it_live==False - using dummy data")
        raw = {"result": "dummy_data"}

    if 'hosts' in raw['result']:
        for host in raw['result']['hosts']:
            if 'ip' in host:
                ips.append(host['ip'])

    return ips

def censys_v2_search_ip(misphunter, event, seed, host_obj):
    
    ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
    service = misphandler.get_attr_val_by_rel(seed, 'service')
    _log.debug(f"Getting raw JSON data from Censys for host {ip}")
    raw = {}
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    auth = (misphunter.censys_v2_id, misphunter.censys_v2_secret)
    
    if misphunter.do_it_live:

        fresh_json = misphandler.check_json_freshness(misphunter, host_obj, service)
        if fresh_json:
            return fresh_json
        else:
            _log.debug(f"Discovered no fresh JSON blobs that are appropriate for reuse.")
        
        _log.debug(f"Using LIVE API query to reach out to Censys and get IP data...")
        try: 
            rate_limit = misphunter.censys_v2_rate
            # Sleep {rate_limit} seconds for each time the search is run
            helper.rate_respect(misphunter.search_time, rate_limit)
            misphunter.search_time = time()
            res = requests.get(url, auth=auth)
            misphunter.censys_v2_api_counter+=1

            _log.debug(f"\n\n#### TOTAL CENSYS API CALLS NOW {misphunter.censys_v2_api_counter}! \n\n")
            if res.status_code == 200:
                raw = json.loads(res.text)
                if misphunter.debugging:
                    _log.debug(f"Results for {ip}: \n\n{raw}")
            else:
                # raise Exception(f"Error getting IP {ip}. Status: {res.status_code} - {res}")
                _log.error(f"Error getting IP {ip}. Status: {res.status_code} - {res}")
                return False
        except Exception as e:
            _log.error(f"Error getting IP {ip}: {e}")
            return False
    
    #### FOR DEBUGGING
    else:
        _log.debug(f"do_it_live==False - using dummy data")
        raw = {'code':200,'status':'OK','result':{'ip':f"{ip}", 'debugging': f"NO DUMMY DATA RETURNED FOR {ip}"}}
    return raw['result']
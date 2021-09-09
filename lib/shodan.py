import json
import logging, logging.handlers, sys

from time import time

import shodan
from shodan import Shodan

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
# _log = get_logger()

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

def shodan_clean_json_keys():
    # This adds a set of keywords to remove for clean comparison of changes
    # across time. e.g. when taking the hash of two blobs of censys data, the
    # hash would change if they both had different time_scraped values. So we
    # want to remove those before the comparison.
    # Looks for keys that END WITH the follow values
    ignored_keys = [
        "timestamp",
        "_shodan",
        "_shodan_crawler",
        "_shodan_module",
        "_shodan_ptr",
        "_shodan_options_scan",
        "last_update",
        "_id"
    ]

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

        except shodan_api.APIError:
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
        raw = {'matches': [{'ip': 624681267, 'product': 'nginx', 'http': {'robots_hash': None, 'redirects': [], 'securitytxt': None, 'title': '302 Found', 'sitemap_hash': None, 'robots': None, 'server': 'nginx, : Server', 'host': '37.59.225.51', 'html': '<html>\r\n<head><title>302 Found</title></head>\r\n<body>\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n', 'location': '/', 'components': {}, 'securitytxt_hash': None, 'sitemap': None, 'html_hash': -23674247}, 'asn': 'AS16276', 'timestamp': '2021-08-08T11:15:51.705887', 'org': 'OVH SAS', 'isp': 'OVH SAS', 'cpe23': ['cpe:2.3:a:igor_sysoev:nginx'], 'cpe': ['cpe:/a:igor_sysoev:nginx'], 'data': 'HTTP/1.1 302 Moved Temporarily\r\nServer: nginx\r\nDate: Sun, 08 Aug 2021 11:15:51 GMT\r\nContent-Type: text/html\r\nContent-Length: 138\r\nConnection: keep-alive\r\nLocation: https://celebs-infor.blogspot.com/\r\nServer:: Server\r\nReferrer-Policy: no-referrer\r\n\r\n', 'port': 443, 'ssl': {'chain_sha256': ['d5f680a63715fa61b02180d2a0206bdd6ec62a1c6cfed5cac4bef175b74e8807'], 'jarm': '2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a', 'chain': ['-----BEGIN CERTIFICATE-----\nMIIG1DCCBbygAwIBAgIQFFc/J3vI5MEIkZtdQNONozANBgkqhkiG9w0BAQsFADCB\njzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQD\nEy5TZWN0aWdvIFJTQSBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENB\nMB4XDTIxMDMwMzAwMDAwMFoXDTIyMDMwMzIzNTk1OVowIDEeMBwGA1UEAxMVY2Vs\nZWJzaW5mb3JtYXRpb24uY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\nAgEAs6FV0MuNdLQ8I78fdtlhFpMFqVUJjGE7jcM2Tio5qAazhfYsg90DrDyM/Nlk\nNfW+rN6s9jSOrrSDWAh9By6X8eafQFZ5DYJCMb0KiURfDJr9fy2k8y/nKcclD1Fm\nQeXA9Pydhu+98YsHQtoc/B9aedNRJPw+apCAiAnTGRK4LyoJ0EP8FgX4nZJPLzRQ\n0bPLmqGtlo/VeSvw0uz1IZE9bwqXtWlomqFsNMEmvBP3ZolEa/coX0rOkMqOZxGb\n1hjb3RZokxxCu6ijKiaBg6noaojQwDgKPJCBJnzxBQIN+CXHQ7DlQL+GgcTdsqmk\nnyd9zprIPt/OWQFl0fG0DFlU+gOxIeA3R7EKW7Ao9A56dH21yHzuZUFAUQ4RhJkg\nNLrucfjOZfd4UgeynPBMi19L8zJLVobVU1sU4SZ5kJmYptt7fSlKKMU8cEZJsNup\nqlJIMAo7YJ6sLgEuPu5UqHHNOu+isvisqvi9N15MmFxBeszX6O7gesVvXgblxv2z\nfwSn0sTqjHLuKYBdQR4ieIq9gljquSBFiGOAsOnSjLWWu/vJfF7S+7RDaYt+lMks\n84Ll2PlnIyIIwFYR1xAq5GcBT4AAsj4pge5BKimPwkbp5dALsAdkidBTHOTua/ge\n5q/iM2aIyHUhJFJWH+y7wLvnyP1OwHzy7APKWhE1ItME9qsCAwEAAaOCApgwggKU\nMB8GA1UdIwQYMBaAFI2MXsRUrYrhd+mb+ZsF4bgBjWHhMB0GA1UdDgQWBBT/oPMa\nijPaZXcRhkZONQ5Kc+Hp1jAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAd\nBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEE\nAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAI\nBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2Ny\ndC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl\ncnZlckNBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20w\nOwYDVR0RBDQwMoIVY2VsZWJzaW5mb3JtYXRpb24uY29tghl3d3cuY2VsZWJzaW5m\nb3JtYXRpb24uY29tMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHUARqVV63X6kSAw\ntaKJafTzfREsQXS+/Um4havy/HD+bUcAAAF39xKbXwAABAMARjBEAiB9Wo1B3cnY\nYimjuKaTST88G4lmFNWEw/elkm1RZQLssQIgGAQilPCpGVTZQHcefwdxOftmWowD\nqX/G/q2lKcbjFzwAdwDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47EsAgRFwqcwAA\nAXf3Eps+AAAEAwBIMEYCIQCgIuxqY5D8mLJxxgzCHfy8VGqP97qfOl03nc05F5PB\nPgIhAJ7lBn02k4Kt7EPXM8RoR57kda2iybkXSJY7xk/IVYc4MA0GCSqGSIb3DQEB\nCwUAA4IBAQAonmYwvY5cW5jlOW8pdoPoDOY+S33C6HeN8k6dK9U0cOu21O9ivZPw\nNUALhQAqIfYdIh46B6/qMqY99l3/oLZS8ycQrs+RynCzwbGJt0I1hSrNLjUbDQLm\nNrmWVSevJZSyca4wS4zObdqJfvJU6moSBMQOgmfPbifq/H5uodarFciZ8Y0xCXP6\ntmhytsx8sLE0yPPkCtr1Xps6s9ebGOf5tBzv+BL+VgO8Dcm6ANvzldBRvlfUfiRp\nd1/yxvRmMbMuPlnOw/jtU+4aHqYWQAB2mDcl5Le6AvWCvICtMjpsv5Ahg2IqvanA\nYSlL9ObH4Llutc5bu0R1vXvb2drz+HSj\n-----END CERTIFICATE-----\n'], 'dhparams': None, 'versions': ['-TLSv1', '-SSLv2', '-SSLv3', '-TLSv1.1', 'TLSv1.2', '-TLSv1.3'], 'acceptable_cas': [], 'tlsext': [{'id': 65281, 'name': 'renegotiation_info'}, {'id': 11, 'name': 'ec_point_formats'}, {'id': 35, 'name': 'session_ticket'}], 'alpn': ['http/1.1'], 'cert': {'sig_alg': 'sha256WithRSAEncryption', 'issued': '20210303000000Z', 'expires': '20220303235959Z', 'pubkey': {'bits': 4096, 'type': 'rsa'}, 'version': 2, 'extensions': [{'data': '0\\x16\\x80\\x14\\x8d\\x8c^\\xc4T\\xad\\x8a\\xe1w\\xe9\\x9b\\xf9\\x9b\\x05\\xe1\\xb8\\x01\\x8da\\xe1', 'name': 'authorityKeyIdentifier'}, {'data': '\\x04\\x14\\xff\\xa0\\xf3\\x1a\\x8a3\\xdaew\\x11\\x86FN5\\x0eJs\\xe1\\xe9\\xd6', 'name': 'subjectKeyIdentifier'}, {'critical': True, 'data': '\\x03\\x02\\x05\\xa0', 'name': 'keyUsage'}, {'critical': True, 'data': '0\\x00', 'name': 'basicConstraints'}, {'data': '0\\x14\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x01\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x02', 'name': 'extendedKeyUsage'}, {'data': '0@04\\x06\\x0b+\\x06\\x01\\x04\\x01\\xb21\\x01\\x02\\x02\\x070%0#\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x02\\x01\\x16\\x17https://sectigo.com/CPS0\\x08\\x06\\x06g\\x81\\x0c\\x01\\x02\\x01', 'name': 'certificatePolicies'}, {'data': '0v0O\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x02\\x86Chttp://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt0#\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x01\\x86\\x17http://ocsp.sectigo.com', 'name': 'authorityInfoAccess'}, {'data': '02\\x82\\x15celebsinformation.com\\x82\\x19www.celebsinformation.com', 'name': 'subjectAltName'}, {'data': '\\x04\\x81\\xf2\\x00\\xf0\\x00u\\x00F\\xa5U\\xebu\\xfa\\x91 0\\xb5\\xa2\\x89i\\xf4\\xf3}\\x11,At\\xbe\\xfdI\\xb8\\x85\\xab\\xf2\\xfcp\\xfemG\\x00\\x00\\x01w\\xf7\\x12\\x9b_\\x00\\x00\\x04\\x03\\x00F0D\\x02 }Z\\x8dA\\xdd\\xc9\\xd8b)\\xa3\\xb8\\xa6\\x93I?<\\x1b\\x89f\\x14\\xd5\\x84\\xc3\\xf7\\xa5\\x92mQe\\x02\\xec\\xb1\\x02 \\x18\\x04"\\x94\\xf0\\xa9\\x19T\\xd9@w\\x1e\\x7f\\x07q9\\xfbfZ\\x8c\\x03\\xa9\\x7f\\xc6\\xfe\\xad\\xa5)\\xc6\\xe3\\x17<\\x00w\\x00\\xdf\\xa5^\\xabh\\x82O\\x1fl\\xad\\xee\\xb8_N>Z\\xea\\xcd\\xa2\\x12\\xa4j^\\x8e;\\x12\\xc0 D\\\\*s\\x00\\x00\\x01w\\xf7\\x12\\x9b>\\x00\\x00\\x04\\x03\\x00H0F\\x02!\\x00\\xa0"\\xecjc\\x90\\xfc\\x98\\xb2q\\xc6\\x0c\\xc2\\x1d\\xfc\\xbcTj\\x8f\\xf7\\xba\\x9f:]7\\x9d\\xcd9\\x17\\x93\\xc1>\\x02!\\x00\\x9e\\xe5\\x06}6\\x93\\x82\\xad\\xecC\\xd73\\xc4hG\\x9e\\xe4u\\xad\\xa2\\xc9\\xb9\\x17H\\x96;\\xc6O\\xc8U\\x878', 'name': 'ct_precert_scts'}], 'fingerprint': {'sha256': 'd5f680a63715fa61b02180d2a0206bdd6ec62a1c6cfed5cac4bef175b74e8807', 'sha1': 'fb4e1c52ea9e482a700a53397fd37a163c8c395d'}, 'serial': 27037570662403737205649684453183950243, 'issuer': {'C': 'GB', 'ST': 'Greater Manchester', 'CN': 'Sectigo RSA Domain Validation Secure Server CA', 'O': 'Sectigo Limited', 'L': 'Salford'}, 'expired': False, 'subject': {'CN': 'celebsinformation.com'}}, 'cipher': {'version': 'TLSv1/SSLv3', 'bits': 256, 'name': 'ECDHE-RSA-AES256-GCM-SHA384'}, 'trust': {'revoked': False, 'browser': None}, 'handshake_states': ['before/connect initialization', 'SSLv2/v3 write client hello', 'SSLv2/v3 read server hello', 'SSLv3/TLS read server hello', 'SSLv3/TLS read server certificate', 'SSLv3/TLS read server key exchange', 'SSLv3/TLS read server done', 'SSLv3/TLS write client key exchange', 'SSLv3/TLS write change cipher spec', 'SSLv3/TLS write finished', 'SSLv3/TLS flush data', 'SSLv3/TLS read server session ticket', 'SSLv3/TLS read finished', 'SSL negotiation finished successfully'], 'ja3s': 'e35df3e00ca4ef31d42b34bebaa2f86e', 'ocsp': {}}, 'hostnames': [], 'transport': 'tcp', 'ip_str': '37.59.225.51', 'domains': [], 'hash': 771084720, 'os': None, '_shodan': {'crawler': '42f86247b760542c0192b61c60405edc5db01d55', 'id': '7c4bae11-60b7-4878-bf8e-e9196811cd2a', 'module': 'https', 'options': {}}, 'location': {'city': 'Wittelsheim', 'region_code': '44', 'area_code': None, 'longitude': 7.24154, 'country_code3': None, 'latitude': 47.80947, 'postal_code': None, 'dma_code': None, 'country_code': 'FR', 'country_name': 'France'}}], 'total': 1}
    
    
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
        raw = {'region_code': '16', 'tags': ['cloud'], 'ip': 3333295395, 'area_code': None, 'domains': ['linode.com'], 'postal_code': None, 'dma_code': None, 'org': 'Linode, LLC', 'ip_str': '192.168.1.100'}
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
        
    except shodan_api.APIError:
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

    except Exception as e:
        mh.logger.error(f"Error getting IP {ip}: {e}")
        # raw = {"error": "IP Not Found"}
        return False
    
    return raw
    

def shodan_search_ip_old(mh, event, seed, host_obj):

    ip = misphandler.get_attr_val_by_rel(host_obj, 'host-ip')
    service = misphandler.get_attr_val_by_rel(seed, 'service')
    mh.logger.debug(f"Getting raw JSON data for {ip}")
    raw = {}
    shodan_api = Shodan(mh.shodan_key)
    
    if mh.do_it_live:
        # Get rate_limit for this service
        rate_limit = mh.shodan_rate
        fresh_json = misphandler.check_json_freshness(mh, host_obj, service)
        if fresh_json:
            return fresh_json
        else:
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
            
        except shodan_api.APIError:
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
                return raw

        except Exception as e:
            mh.logger.error(f"Error getting IP {ip}: {e}")
            # raw = {"error": "IP Not Found"}
            return raw
    
    #### FOR DEBUGGING
    else:
        mh.logger.debug(f"do_it_live==False - using dummy data")
        raw = {'region_code': '16', 'tags': ['cloud'], 'ip': 3224295394, 'area_code': None, 'domains': ['linode.com'], 'hostnames': ['li2207-226.members.linode.com'], 'postal_code': None, 'dma_code': None, 'country_code': 'IN', 'org': 'Linode, LLC', 'data': [{'hash': 856668804, 'tags': ['cloud'], 'timestamp': '2021-08-11T12:41:42.802026', 'org': 'Linode, LLC', 'isp': 'Linode, LLC', 'data': 'whoami\n', 'asn': 'AS63949', 'port': 443, 'cloud': {'region': 'in-mh', 'service': None, 'provider': 'Linode'}, 'hostnames': ['li2207-226.members.linode.com'], 'transport': 'tcp', 'ip': 3224295394, 'domains': ['linode.com'], 'ip_str': '192.46.215.226', 'os': None, '_shodan': {'crawler': 'd905ab419aeb10e9c57a336c7e1aa9629ae4a733', 'ptr': True, 'id': '0d82f299-f630-4962-9e93-61ee7a0e65e3', 'module': 'https', 'options': {}}, 'opts': {}, 'location': {'city': 'Mumbai', 'region_code': '16', 'area_code': None, 'longitude': 72.88261, 'country_code3': None, 'latitude': 19.07283, 'postal_code': None, 'dma_code': None, 'country_code': 'IN', 'country_name': 'India'}}, {'ip': 3224295394, 'asn': 'AS63949', 'http': {'robots_hash': None, 'redirects': [{'host': '192.46.215.226', 'data': 'HTTP/1.1 302 Found\r\nContent-Type: text/html; charset=utf-8\r\nLocation: /login/index\r\nServer: beegoServer:1.12.0\r\nSet-Cookie: beegosessionID=5b7f84e2df99c067ae67293cd5fc67c3; Path=/; HttpOnly\r\nDate: Mon, 02 Aug 2021 13:39:27 GMT\r\nContent-Length: 35\r\n\r\n', 'location': '/'}], 'securitytxt': None, 'title': 'beego application error', 'sitemap_hash': None, 'robots': None, 'server': 'beegoServer:1.12.0', 'host': '192.46.215.226', 'html': '\n<!DOCTYPE html>\n<html>\n<head>\n    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />\n    <title>beego application error</title>\n    <style>\n      html, body, body * {padding: 0; margin: 0;}\n        #header {background:#ffd; border-bottom:solid 2px #A31515; padding: 20px 10px;}\n        #header h2{ }\n        #footer {border-top:solid 1px #aaa; padding: 5px 10px; font-size: 12px; color:green;}\n        #content {padding: 5px;}\n        #content .stack b{ font-size: 13px; color: red;}\n  #content .stack pre{padding-left: 10px;}\n        table {}\n        td.t {text-align: right; padding-right: 5px; color: #888;}\n    </style>\n    <script type="text/javascript">\n    </script>\n</head>\n<body>\n    <div id="header">\n        <h2>nps:can&#39;t find templatefile in the path:/root/web/views/login/index.html</h2>\n    </div>\n    <div id="content">\n        <table>\n            <tr>\n                <td class="t">Request Method: </td><td>GET</td>\n            </tr>\n            <tr>\n                <td class="t">Request URL: </td><td>/login/index</td>\n            </tr>\n            <tr>\n                <td class="t">RemoteAddr: </td><td>230.166.46.80</td>\n            </tr>\n        </table>\n        <div class="stack">\n            <b>Stack</b>\n            <pre>/opt/hostedtoolcache/go/1.15.2/x64/src/runtime/panic.go:969\n/home/runner/go/pkg/mod/github.com/exfly/beego@v1.12.0-export-init/template.go:75\n/home/runner/go/pkg/mod/github.com/exfly/beego@v1.12.0-export-init/controller.go:306\n/home/runner/go/pkg/mod/github.com/exfly/beego@v1.12.0-export-init/controller.go:257\n/home/runner/go/pkg/mod/github.com/exfly/beego@v1.12.0-export-init/controller.go:237\n/home/runner/go/pkg/mod/github.com/exfly/beego@v1.12.0-export-init/router.go:865\n/opt/hostedtoolcache/go/1.15.2/x64/src/net/http/server.go:2843\n/opt/hostedtoolcache/go/1.15.2/x64/src/net/http/server.go:1925\n/opt/hostedtoolcache/go/1.15.2/x64/src/runtime/asm_amd64.s:1374\n</pre>\n        </div>\n    </div>\n    <div id="footer">\n        <p>beego 1.12.0 (beego framework)</p>\n        <p>golang version: go1.15.2</p>\n    </div>\n</body>\n</html>\n', 'location': '/login/index', 'components': {}, 'securitytxt_hash': None, 'sitemap': None, 'html_hash': 105053350}, 'tags': ['cloud'], 'timestamp': '2021-08-02T13:39:27.925186', 'org': 'Linode, LLC', 'isp': 'Linode, LLC', 'data': 'HTTP/1.1 200 OK\r\nServer: beegoServer:1.12.0\r\nSet-Cookie: beegosessionID=a471a3add3f3ba647414c77bc54aa8ff; Path=/; HttpOnly\r\nDate: Mon, 02 Aug 2021 13:39:27 GMT\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n', 'port': 8080, 'cloud': {'region': 'in-mh', 'service': None, 'provider': 'Linode'}, 'hostnames': ['li2207-226.members.linode.com'], 'transport': 'tcp', 'ip_str': '192.46.215.226', 'domains': ['linode.com'], 'hash': -37714238, 'os': None, '_shodan': {'crawler': '85a5be66a1913a867d4f8cd62bd10fb79f410a2a', 'ptr': True, 'id': 'f0055d27-3066-4d43-a4ad-0f88366c82df', 'module': 'http-simple-new', 'options': {}}, 'opts': {}, 'location': {'city': 'Mumbai', 'region_code': '16', 'area_code': None, 'longitude': 72.88261, 'country_code3': None, 'latitude': 19.07283, 'postal_code': None, 'dma_code': None, 'country_code': 'IN', 'country_name': 'India'}}], 'asn': 'AS63949', 'city': 'Mumbai', 'latitude': 19.07283, 'isp': 'Linode, LLC', 'longitude': 72.88261, 'last_update': '2021-08-11T12:41:42.802026', 'country_code3': None, 'country_name': 'India', 'ip_str': '192.46.215.226', 'os': None, 'ports': [8080, 443]}

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

        except shodan_api.APIError:
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
        raw = {'matches': [{'ip': 624681267, 'product': 'nginx', 'http': {'robots_hash': None, 'redirects': [], 'securitytxt': None, 'title': '302 Found', 'sitemap_hash': None, 'robots': None, 'server': 'nginx, : Server', 'host': '37.59.225.51', 'html': '<html>\r\n<head><title>302 Found</title></head>\r\n<body>\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n', 'location': '/', 'components': {}, 'securitytxt_hash': None, 'sitemap': None, 'html_hash': -23674247}, 'asn': 'AS16276', 'timestamp': '2021-08-08T11:15:51.705887', 'org': 'OVH SAS', 'isp': 'OVH SAS', 'cpe23': ['cpe:2.3:a:igor_sysoev:nginx'], 'cpe': ['cpe:/a:igor_sysoev:nginx'], 'data': 'HTTP/1.1 302 Moved Temporarily\r\nServer: nginx\r\nDate: Sun, 08 Aug 2021 11:15:51 GMT\r\nContent-Type: text/html\r\nContent-Length: 138\r\nConnection: keep-alive\r\nLocation: https://celebs-infor.blogspot.com/\r\nServer:: Server\r\nReferrer-Policy: no-referrer\r\n\r\n', 'port': 443, 'ssl': {'chain_sha256': ['d5f680a63715fa61b02180d2a0206bdd6ec62a1c6cfed5cac4bef175b74e8807'], 'jarm': '2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a', 'chain': ['-----BEGIN CERTIFICATE-----\nMIIG1DCCBbygAwIBAgIQFFc/J3vI5MEIkZtdQNONozANBgkqhkiG9w0BAQsFADCB\njzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQD\nEy5TZWN0aWdvIFJTQSBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENB\nMB4XDTIxMDMwMzAwMDAwMFoXDTIyMDMwMzIzNTk1OVowIDEeMBwGA1UEAxMVY2Vs\nZWJzaW5mb3JtYXRpb24uY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\nAgEAs6FV0MuNdLQ8I78fdtlhFpMFqVUJjGE7jcM2Tio5qAazhfYsg90DrDyM/Nlk\nNfW+rN6s9jSOrrSDWAh9By6X8eafQFZ5DYJCMb0KiURfDJr9fy2k8y/nKcclD1Fm\nQeXA9Pydhu+98YsHQtoc/B9aedNRJPw+apCAiAnTGRK4LyoJ0EP8FgX4nZJPLzRQ\n0bPLmqGtlo/VeSvw0uz1IZE9bwqXtWlomqFsNMEmvBP3ZolEa/coX0rOkMqOZxGb\n1hjb3RZokxxCu6ijKiaBg6noaojQwDgKPJCBJnzxBQIN+CXHQ7DlQL+GgcTdsqmk\nnyd9zprIPt/OWQFl0fG0DFlU+gOxIeA3R7EKW7Ao9A56dH21yHzuZUFAUQ4RhJkg\nNLrucfjOZfd4UgeynPBMi19L8zJLVobVU1sU4SZ5kJmYptt7fSlKKMU8cEZJsNup\nqlJIMAo7YJ6sLgEuPu5UqHHNOu+isvisqvi9N15MmFxBeszX6O7gesVvXgblxv2z\nfwSn0sTqjHLuKYBdQR4ieIq9gljquSBFiGOAsOnSjLWWu/vJfF7S+7RDaYt+lMks\n84Ll2PlnIyIIwFYR1xAq5GcBT4AAsj4pge5BKimPwkbp5dALsAdkidBTHOTua/ge\n5q/iM2aIyHUhJFJWH+y7wLvnyP1OwHzy7APKWhE1ItME9qsCAwEAAaOCApgwggKU\nMB8GA1UdIwQYMBaAFI2MXsRUrYrhd+mb+ZsF4bgBjWHhMB0GA1UdDgQWBBT/oPMa\nijPaZXcRhkZONQ5Kc+Hp1jAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAd\nBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEE\nAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAI\nBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2Ny\ndC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl\ncnZlckNBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20w\nOwYDVR0RBDQwMoIVY2VsZWJzaW5mb3JtYXRpb24uY29tghl3d3cuY2VsZWJzaW5m\nb3JtYXRpb24uY29tMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHUARqVV63X6kSAw\ntaKJafTzfREsQXS+/Um4havy/HD+bUcAAAF39xKbXwAABAMARjBEAiB9Wo1B3cnY\nYimjuKaTST88G4lmFNWEw/elkm1RZQLssQIgGAQilPCpGVTZQHcefwdxOftmWowD\nqX/G/q2lKcbjFzwAdwDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47EsAgRFwqcwAA\nAXf3Eps+AAAEAwBIMEYCIQCgIuxqY5D8mLJxxgzCHfy8VGqP97qfOl03nc05F5PB\nPgIhAJ7lBn02k4Kt7EPXM8RoR57kda2iybkXSJY7xk/IVYc4MA0GCSqGSIb3DQEB\nCwUAA4IBAQAonmYwvY5cW5jlOW8pdoPoDOY+S33C6HeN8k6dK9U0cOu21O9ivZPw\nNUALhQAqIfYdIh46B6/qMqY99l3/oLZS8ycQrs+RynCzwbGJt0I1hSrNLjUbDQLm\nNrmWVSevJZSyca4wS4zObdqJfvJU6moSBMQOgmfPbifq/H5uodarFciZ8Y0xCXP6\ntmhytsx8sLE0yPPkCtr1Xps6s9ebGOf5tBzv+BL+VgO8Dcm6ANvzldBRvlfUfiRp\nd1/yxvRmMbMuPlnOw/jtU+4aHqYWQAB2mDcl5Le6AvWCvICtMjpsv5Ahg2IqvanA\nYSlL9ObH4Llutc5bu0R1vXvb2drz+HSj\n-----END CERTIFICATE-----\n'], 'dhparams': None, 'versions': ['-TLSv1', '-SSLv2', '-SSLv3', '-TLSv1.1', 'TLSv1.2', '-TLSv1.3'], 'acceptable_cas': [], 'tlsext': [{'id': 65281, 'name': 'renegotiation_info'}, {'id': 11, 'name': 'ec_point_formats'}, {'id': 35, 'name': 'session_ticket'}], 'alpn': ['http/1.1'], 'cert': {'sig_alg': 'sha256WithRSAEncryption', 'issued': '20210303000000Z', 'expires': '20220303235959Z', 'pubkey': {'bits': 4096, 'type': 'rsa'}, 'version': 2, 'extensions': [{'data': '0\\x16\\x80\\x14\\x8d\\x8c^\\xc4T\\xad\\x8a\\xe1w\\xe9\\x9b\\xf9\\x9b\\x05\\xe1\\xb8\\x01\\x8da\\xe1', 'name': 'authorityKeyIdentifier'}, {'data': '\\x04\\x14\\xff\\xa0\\xf3\\x1a\\x8a3\\xdaew\\x11\\x86FN5\\x0eJs\\xe1\\xe9\\xd6', 'name': 'subjectKeyIdentifier'}, {'critical': True, 'data': '\\x03\\x02\\x05\\xa0', 'name': 'keyUsage'}, {'critical': True, 'data': '0\\x00', 'name': 'basicConstraints'}, {'data': '0\\x14\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x01\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x02', 'name': 'extendedKeyUsage'}, {'data': '0@04\\x06\\x0b+\\x06\\x01\\x04\\x01\\xb21\\x01\\x02\\x02\\x070%0#\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x02\\x01\\x16\\x17https://sectigo.com/CPS0\\x08\\x06\\x06g\\x81\\x0c\\x01\\x02\\x01', 'name': 'certificatePolicies'}, {'data': '0v0O\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x02\\x86Chttp://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt0#\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x01\\x86\\x17http://ocsp.sectigo.com', 'name': 'authorityInfoAccess'}, {'data': '02\\x82\\x15celebsinformation.com\\x82\\x19www.celebsinformation.com', 'name': 'subjectAltName'}, {'data': '\\x04\\x81\\xf2\\x00\\xf0\\x00u\\x00F\\xa5U\\xebu\\xfa\\x91 0\\xb5\\xa2\\x89i\\xf4\\xf3}\\x11,At\\xbe\\xfdI\\xb8\\x85\\xab\\xf2\\xfcp\\xfemG\\x00\\x00\\x01w\\xf7\\x12\\x9b_\\x00\\x00\\x04\\x03\\x00F0D\\x02 }Z\\x8dA\\xdd\\xc9\\xd8b)\\xa3\\xb8\\xa6\\x93I?<\\x1b\\x89f\\x14\\xd5\\x84\\xc3\\xf7\\xa5\\x92mQe\\x02\\xec\\xb1\\x02 \\x18\\x04"\\x94\\xf0\\xa9\\x19T\\xd9@w\\x1e\\x7f\\x07q9\\xfbfZ\\x8c\\x03\\xa9\\x7f\\xc6\\xfe\\xad\\xa5)\\xc6\\xe3\\x17<\\x00w\\x00\\xdf\\xa5^\\xabh\\x82O\\x1fl\\xad\\xee\\xb8_N>Z\\xea\\xcd\\xa2\\x12\\xa4j^\\x8e;\\x12\\xc0 D\\\\*s\\x00\\x00\\x01w\\xf7\\x12\\x9b>\\x00\\x00\\x04\\x03\\x00H0F\\x02!\\x00\\xa0"\\xecjc\\x90\\xfc\\x98\\xb2q\\xc6\\x0c\\xc2\\x1d\\xfc\\xbcTj\\x8f\\xf7\\xba\\x9f:]7\\x9d\\xcd9\\x17\\x93\\xc1>\\x02!\\x00\\x9e\\xe5\\x06}6\\x93\\x82\\xad\\xecC\\xd73\\xc4hG\\x9e\\xe4u\\xad\\xa2\\xc9\\xb9\\x17H\\x96;\\xc6O\\xc8U\\x878', 'name': 'ct_precert_scts'}], 'fingerprint': {'sha256': 'd5f680a63715fa61b02180d2a0206bdd6ec62a1c6cfed5cac4bef175b74e8807', 'sha1': 'fb4e1c52ea9e482a700a53397fd37a163c8c395d'}, 'serial': 27037570662403737205649684453183950243, 'issuer': {'C': 'GB', 'ST': 'Greater Manchester', 'CN': 'Sectigo RSA Domain Validation Secure Server CA', 'O': 'Sectigo Limited', 'L': 'Salford'}, 'expired': False, 'subject': {'CN': 'celebsinformation.com'}}, 'cipher': {'version': 'TLSv1/SSLv3', 'bits': 256, 'name': 'ECDHE-RSA-AES256-GCM-SHA384'}, 'trust': {'revoked': False, 'browser': None}, 'handshake_states': ['before/connect initialization', 'SSLv2/v3 write client hello', 'SSLv2/v3 read server hello', 'SSLv3/TLS read server hello', 'SSLv3/TLS read server certificate', 'SSLv3/TLS read server key exchange', 'SSLv3/TLS read server done', 'SSLv3/TLS write client key exchange', 'SSLv3/TLS write change cipher spec', 'SSLv3/TLS write finished', 'SSLv3/TLS flush data', 'SSLv3/TLS read server session ticket', 'SSLv3/TLS read finished', 'SSL negotiation finished successfully'], 'ja3s': 'e35df3e00ca4ef31d42b34bebaa2f86e', 'ocsp': {}}, 'hostnames': [], 'transport': 'tcp', 'ip_str': '37.59.225.51', 'domains': [], 'hash': 771084720, 'os': None, '_shodan': {'crawler': '42f86247b760542c0192b61c60405edc5db01d55', 'id': '7c4bae11-60b7-4878-bf8e-e9196811cd2a', 'module': 'https', 'options': {}}, 'location': {'city': 'Wittelsheim', 'region_code': '44', 'area_code': None, 'longitude': 7.24154, 'country_code3': None, 'latitude': 47.80947, 'postal_code': None, 'dma_code': None, 'country_code': 'FR', 'country_name': 'France'}}], 'total': 1}

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
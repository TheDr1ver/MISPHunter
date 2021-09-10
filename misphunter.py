import argparse
import configparser
import logging
import urllib3

from pprint import pformat
from time import time, sleep

from pymisp import PyMISP

from lib import helper, huntlogic, misphandler

class MISPHunter():
    def __init__(self, logger=None):

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
        #### Debugging-specific vars
        # Overall Debugging Var - used for activating certain overly-verbose logs
        self.debugging = True
        # Set to False to use dummy Censys data
        self.do_it_live = True
        # Force extraction of IOCs, regardless of JSON blob diff/age
        self.force_ioc_extract = False
        # Ignore timers set for seed objects - don't read them, 
        # don't write them, just run API calls with reckless abandon
        self.ignore_timers = False
        
        #### Everyday vars
        # Enable verbose logging
        self.verbose_logging = False
        # Scrub dates from JSON blobs (time/process intensive) - probably mark 
        #   this for future deprecation
        self.remove_dates = False
        # Use certificates found in JSON blobs to create pivot objects and 
        # potentially find new hosts. Probably should force this regardless.
        self.cert_pivoting = True
        # maxmium number of hosts a certificate can return before being truncated
        self.cert_pivot_threshold = 20 
        # Determines how old an object can be before using API calls to update 
        # it. Defaults to 24.
        self.update_threshold = 24
        # hours before an attribute is no longer considered newly-discovered and
        # the new-discovery tags are removed.
        self.new_discovery_threshold = 72

        self.logger = helper.get_logger(verbose=self.verbose_logging)
        
                
        # Read configs
        try:
            config = configparser.ConfigParser()
            config.read('./misphunter.conf')
            self.misp_url = config['MISP']['misp_url']
            self.misp_key = config['MISP']['misp_api']

            self.censys_v1_active = config['censys-v1']['active']
            self.censys_v1_id = config['censys-v1']['id']
            self.censys_v1_secret = config['censys-v1']['secret']
            self.censys_v1_rate = int(config['censys-v1']['rate_limit'])
            self.censys_v1_slug = config['censys-v1']['slug']
            self.censys_v1_api_counter = 0
            
            self.censys_v2_active = config['censys-v2']['active']
            self.censys_v2_id = config['censys-v2']['id']
            self.censys_v2_secret = config['censys-v2']['secret']
            self.censys_v2_rate = int(config['censys-v2']['rate_limit'])
            self.censys_v2_slug = config['censys-v2']['slug']
            self.censys_v2_api_counter = 0
            
            self.shodan_active = config['shodan']['active']
            self.shodan_key = config['shodan']['api']
            self.shodan_rate = int(config['shodan']['rate_limit'])
            self.shodan_slug = config['shodan']['slug']
            self.shodan_api_counter = 0

            self.ignored_json_keys = {}
                        
            self.logger.info("\n\nLoaded configs okay...")
            

        except Exception as ex:
            self.logger.error(
                f"Exception: {ex} - occurred loading configs", exc_info=True)
            raise

        try:
            self.misp = PyMISP(self.misp_url, self.misp_key, False)
        except Exception as ex:
            self.logger.error(
                f"Exception: {ex}  - occurred while loading MISP", exc_info=True)
            raise

    def run(self):
        self.logger.info(f"\n###############################################################################\n\n# "\
                "GIDDY-UP, HUNTER!\n"\
                ",______________________________________\n"
                "|_________________,----------._ [____]  \"\"-,__  __....-----=====\n"
                "               (_(||||||||||||)___________/   \"\"                |\n"
                "                  `----------'        [ ))\"-,                   |\n"
                "                                       \"\"    `,  _,--....___    |\n"
                "                                               `/           \"\"\"\"\n"
                "\n###############################################################################\n\n")
        # Reset stats for each run
        self.run_stats = {
            "auto_blacklists_added" : {'total': 0},
            "certs_added": {'total': 0},
            "clones_added": {'total': 0},
            "hosts_added": {'total': 0},
            "tags_added": {'total': 0},
            "tags_removed": {'total': 0}
        }
        # Track start time for overall time it takes the script to run
        self.start_time = time()
        self.logger.debug(f"Running MISPHunter... Starting timer  at {self.start_time}!")
        # Set initial search time for API request limits
        self.search_time = time()

        # Search MISP for globally blocked IPs & create global block list
        self.global_blocks = misphandler.get_global_blocks(self)

        # Get groups of different seed types. Seeds are objets that start an event. 
        # Right now these are censys-v2 and shodan...
        self.host_seed_services = []
        if self.censys_v1_active:
            self.host_seed_services.append(self.censys_v1_slug)
        if self.censys_v2_active:
            self.host_seed_services.append(self.censys_v2_slug)
        if self.shodan_active:
            self.host_seed_services.append(self.shodan_slug)

        # ...In the future, these can be seeds that return different types of results 
        # (like a list of domains instead of IPs) 
        # from things like RiskIQ, Domaintools, and even VirusTotal

        # TODO
        # self.dns_seed_services = []
        # if self.domaintools_active:
        #     self.dns_seed_services.append(self.domaintools_slug)

        if self.do_it_live:
            self.logger.info(f"THIS IS NOT A DRILL! - Using actual API queries instead of dummy data.")
        
        # Get all enabled MISP seed objects and their parent event IDs
        all_event_seeds = misphandler.get_all_event_seeds(self)

        # Loop through events one at a time
        for event_id, seeds in all_event_seeds.items():
            ### DEBUGGING
            if str(event_id) != "3978":
                continue

            event = misphandler.get_event(self, event_id)
            self.logger.info(f"\n###############################################################################\n\n# "
                f"PROCESSING EVENT ID {event_id}\n# "
                f"{event.info}"
                f"\n###############################################################################\n\n")
            mh.event_hosts = misphandler.get_event_objects(self, event, 'misphunter-host')
            # Above sets global lists of MISPObjects like mh.event_hosts = [<misphunter-host>, <misphunter-host>]
            mh.event_seeds = misphandler.get_event_objects(self, event, 'misphunter-seed')
            # mh.event_seeds = [<misphunter-seed>]
            mh.event_certs = misphandler.get_event_objects(self, event, 'misphunter-cert')
            # mh.event_certs = [<misphunter-cert>]
            # TODO - still haven't built these objects yet
            #   Issues #15 and #16
            mh.event_dns = misphandler.get_event_objects(self, event, 'misphunter-dns')
            # mh.event_dns = [<misphunter-dns>]
            mh.event_malware = misphandler.get_event_objects(self, event, 'misphunter-malware')
            # mh.event_malware = [<misphunter-malware>]

            # Reset updated objects and found pivots for each event processed
            # mh.event_new_objects = []
            # mh.event_new_object_uuids = []
            mh.event_staged_objects = []
            mh.event_processed_object_uuids = []

            mh.obj_index_mapping = {
                "misphunter-seed": "search-string",
                "misphunter-host": "host-ip",
                "misphunter-cert": "cert-sha256",
                "misphunter-dns": "domain",
                "misphunter-malware": "sha256"
            }

            mh.rel_type_mapping = {
                "search-string": "text",
                "host-ip": "ip-dst",
                "cert-sha256": "x509-fingerprint-sha256",
                "domain": "domain",
                "sha256": "sha256"
            }

            mh.obj_pivot_mapping = {
                "misphunter-seed": {
                    "found-host" : "misphunter-host"
                },
                "misphunter-host": {
                    "extracted-certificate": "misphunter-cert",
                    "extracted-domain": "misphunter-domain"
                },
                "misphunter-cert": {
                    "cert-ip": "misphunter-host"
                }
            }
            
            # First, process seeds
            # event = huntlogic.process_seeds(self, seeds, event)
            # process_seeds -> for each seed:
            #   process_hosts -> for each host IP found by the seed search:
            #       cert_pivot -> get all certs living on host. For each cert, create a misphunter-cert object. 
            #       for each misphunter-cert object:
            #           IMPORTANT: IF CERT IS TRASH/BLACKLISTED, SKIP PROCESS_CERT_IPS
            #           process_cert_ips -> For all the IPs found in each cert,
            #               process_hosts with the original seed and the IPs found related to that cert.

            ### Simplified logic - First attempt failed
            # Process seeds - this will any host objects the seeds discovered to mh.event_new_objects
            # huntlogic.process_seeds(self, seeds, event)
            # Continue processing new_event_objects until they're exhausted
            # Processing host objects should generate cert objects, and vice-versa
            # event = huntlogic.process_event_new_objects(self, event)

            ### 2-Stage Process
            event = huntlogic.set_the_stage(self, seeds, event)
            self.logger.debug(f"Initial processing stage before being processed:\n\n"
                f"{pformat(mh.event_staged_objects)}")
            
            # continue processing event_staged_objects until they're exhausted
            # as each event is processed from the stage, add its UUID to 
            #   event_processed_object_uuids and remove it from event_staged_objects
            event = huntlogic.process_stage(self, event)
            

            # TODO - Issue #3
            # Second, process all enabled misphunter objects for this event that were not touched after process_seeds()
            #   Might want to handle this differently than I originally thought. 
            #   If a host no longer shows up in a seed search, how can we tell if it's still related?
            #   Should it then be disabled?

            # Third, run relationships/relationship checks against all objects in the event.
            event = huntlogic.process_relationships(self, event)

            # Tag/Untag event and individual attributes as "new" if newly added within update_threshold
            event = huntlogic.process_new_tags(self, event)

            # Finally, set blacklisted=1 for objects that have a crappy return (e.g. certs with only 1 assoc. host)
            #   or dns/domain objects that are clearly shared hosts
            event = huntlogic.auto_blacklist(self, event)

        total_api = self.censys_v2_api_counter + self.shodan_api_counter
        self.logger.info(f"\n\nTOTAL CENSYS API CALLS: {self.censys_v2_api_counter}\n"
            f"TOTAL SHODAN API CALLS: {self.shodan_api_counter}\n"
            f"TOTAL OVERALL EXTERNAL API CALLS: {total_api}\n\n")
        self.logger.info(f"Other stats:")
        for k, v in self.run_stats.items():
            self.logger.info(f"{k}:")
            self.logger.info(f"    {pformat(v)}")
        # self.logger.info({pformat(self.run_stats)})
        self.logger.info("DONE!")

def run_as_service(mh):
    mh.logger.info(f"Launching MISPHunter as a service...")
    while True:
        chk_file = "./misphunter_chkpt.txt"
        try:
            checkpoint = open(chk_file)
            chk = checkpoint.readline()
            checkpoint.close()
        except:
            chk = 0
        
        end_sec = time()
        end_sec_int = int(end_sec)
        one_hour = 60 * 60
        one_day = one_hour * 24
        two_day = one_day * 2
        seconds_passed = end_sec_int-int(chk)
        if seconds_passed >= one_hour:
            mh.run()
            mh.logger.info(f"Saving new checkpoint of {end_sec}.")
            f = open(chk_file,'w')
            new_checkpoint = str(int(end_sec)+1)
            f.write(new_checkpoint)
            f.close()
            sleep(one_hour+1)
        else:
            time_remaining = (one_hour+1) - seconds_passed
            mh.logger.info(f"Only {seconds_passed} seconds have passed since the last time we ran MISPHunter. Sleeping for remaining {time_remaining} seconds.")
            sleep(time_remaining)

if __name__ == "__main__":

    # Process CLI arguments
    msg = "MISPHunter"
    parser = argparse.ArgumentParser(description = msg)

    parser.add_argument("--cert-pivot-threshold", type=int, default=10,
        help="Maxmium number of hosts a certificate pivot can return before being truncated. Defaults to 10.")
    parser.add_argument("--new-discovery-threshold", type=int, default=72,
        help="Maximum number of hours before an attribute is no longer considered newly-discovered and the new-discovery "\
            "tags get removed. Defaults to 72.")
    parser.add_argument("--update-threshold", type=int, default=24,
        help="Determines how old an object can be before using API calls to update it. Defaults to 24.")
    parser.add_argument("-s", "--run-as-service", action="store_true",
        help="Run MISPHunter as a service. This puts it into an infinite loop where it runs once an hour.")
    parser.add_argument("--debugging", action="store_true",
        help="[DEBUG] Set debugging flag to true. Blows up your logs.")
    parser.add_argument("--offline", action="store_false",
        help="[DEBUG] Forces 'offline' mode, causing no 3rd party API queries to be used.")
    parser.add_argument("--ignore-timers", action="store_true",
        help="[DEBUG] Ignore the age of objects and process everything with live API requests.")
    parser.add_argument("--force-ioc-extract", action="store_true",
        help="[DEBUG] Force IOC extraction on all discovered objects, regardless of their age.")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Enable DEBUG-level logging.")

    # Initialize parser
    
    args = parser.parse_args()

    mh = MISPHunter()

    # DEBUGGING Vars
    mh.debugging = args.debugging
    mh.do_it_live = args.offline
    mh.force_ioc_extract = args.force_ioc_extract
    mh.ignore_timers = args.ignore_timers
    # I think this was removed entirely, so probably can be scrubbed.
    # mh.update_misp = True

    # EVERYDAY Vars
    mh.verbose_logging = args.verbose
    # Determines how old an object can be before using API calls to update 
    # it. Defaults to 24.
    mh.update_threshold = args.update_threshold
    # Use certificates found in JSON blobs to create pivot objects and 
    # potentially find new hosts. Probably should force this regardless.
    mh.cert_pivoting = True
    # maxmium number of hosts a certificate pivot can return before 
    # being truncated
    mh.cert_pivot_threshold = args.cert_pivot_threshold
    # hours before an attribute is no longer considered newly-discovered and
    # the new-discovery tags are removed.
    mh.new_discovery_threshold = args.new_discovery_threshold

    # Service flag
    service = args.run_as_service

    # DEBUG - REMOVE ME
    if mh.debugging:
        mh.logger.debug(f"debugging: {mh.debugging}")
        mh.logger.debug(f"do_it_live: {mh.do_it_live}")
        mh.logger.debug(f"force_ioc_extract: {mh.force_ioc_extract}")
        mh.logger.debug(f"ignore_timers: {mh.ignore_timers}")
        mh.logger.debug(f"verbose_logging: {mh.verbose_logging}")
        mh.logger.debug(f"update_threshold: {mh.update_threshold}")
        mh.logger.debug(f"cert_pivoting: {mh.cert_pivoting}")
        mh.logger.debug(f"cert_pivot_threshold: {mh.cert_pivot_threshold}")
        mh.logger.debug(f"new_discovery_threshold: {mh.new_discovery_threshold}")
        mh.logger.debug(f"run_as_service: {service}")

    # Set verbose logging
    if mh.verbose_logging:
        mh.logger.setLevel(logging.DEBUG)
        mh.logger.debug(f"Verbose logging enabled!")

    if service:
        run_as_service(mh)
    else:
        mh.logger.info("Service flag set to False. Running MISPHunter once then exiting.")
        mh.run()

    
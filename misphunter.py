import configparser
from pprint import pformat
from time import time, sleep
import urllib3

from pymisp import PyMISP

from lib import helper, huntlogic, misphandler

class MISPHunter():
    def __init__(self, logger=None):

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.logger = helper.get_logger()
        
        #### Debugging-specific vars
        # Debugging Var
        self.debugging = True
        # Used for debugging - set to False to use dummy Censys data
        self.do_it_live = True
        
        # Force extraction of IOCs, regardless of JSON blob diff/age
        self.force_ioc_extract = False
        # Scrub dates from JSON blobs (time/process intensive)
        self.remove_dates = False
        # Use certificates found in JSON blobs to create pivot objects and potentially find new hosts
        self.cert_pivoting = True
        # maxmium number of hosts a certificate can return before being truncated
        self.cert_pivot_threshold = 20 
        # Determines how old an object can be before using API calls to update it. Defaults to 24.
        self.update_threshold = 24
        
                
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
            self.run_stats = {}
            
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
            event = misphandler.get_event(self, event_id)
            self.logger.info(f"\n###############################################################################\n\n# "
                f"PROCESSING EVENT ID {event_id}\n# "
                f"{event.info}"
                f"\n###############################################################################\n\n")
            misphandler.get_event_hosts(self, event)
            # Above sets global lists of MISPObjects like misphunter.event_hosts = [event_hosts]
            misphandler.get_event_seeds(self, event)
            misphandler.get_event_certs(self, event)
            # TODO
            misphandler.get_event_dns(self, event)
            # TODO
            misphandler.get_event_malware(self, event)
            
            # First, process seeds
            event = huntlogic.process_seeds(self, seeds, event)
            # process_seeds -> for each seed:
            #   process_hosts -> for each host IP found by the seed search:
            #       cert_pivot -> get all certs living on host. For each cert, create a misphunter-cert object. 
            #       for each cert_pivot object:
            #           process_cert_ips -> For all the IPs found in each cert,
            #               process_hosts with the original seed and the IPs found related to that cert.

            # TODO
            # Second, process all enabled misphunter objects for this event that were not touched after process_seeds()

            # Third, run relationships/relationship checks against all objects in the event.
            event = huntlogic.process_relationships(self, event)

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

if __name__ == "__main__":
    mh = MISPHunter()

    mh.debugging = False
    mh.force_ioc_extract = False
    mh.update_misp = True

    mh.do_it_live = True
    mh.ignore_timers = False
    mh.update_threshold = 24
    mh.cert_pivoting = True
    mh.cert_pivot_threshold = 10

    # mh.run()

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
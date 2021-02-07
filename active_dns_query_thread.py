import time
from scapy.all import *
from typing import List
import os
import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
from network_tools import *
from db_functions import *
import pudb
from random import randint


logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
#logger = logging.getLogger(__name__)


def update_dns():

    #print('Running update_dns() in thread')
    stepBack=1
    while True:
        logging.debug('Running update_dns() in thread')
 
        #get domains to block from DB
        #domains=db_get_domains()
        disneyPlusDomains={"parentDomain":'DisneyPlus',
                "subdomains":['disneyplus.com','bam.nr-data.net','cdn.registerdisney.go.com','cws.conviva.com', 'd9.flashtalking.com','disney-portal.my.onetrust.com','disneyplus.bn5x.net','js-agent.newrelic.com']}
        netflixDomains={"parentDomain":'Netflix',
                "subdomains":['netflix.com','netflix.net','nflxext.com','nflximg.com','nflxvideo.net']}
        youtubeDomains={"parentDomain":'Youtube',
                "subdomains":['youtube.com','googlevideo.com','youtu.be','youtube-ui.l.google.com','ytimg.l.google.com','ytstatic.l.google.com','youtubei.googleapis.com']}
        #domains=disneyPlusDomains + netflixDomains + youtubeDomains
        whitelist={"parentDomain":'Whitelist',
        "subdomains":['tunein.com','spotify.com','spotify.ca','spotify.net']}
        tiktokDomains={"parentDomain":'Tiktok',
                "subdomains":['v16a.tiktokcdn.com',
                'p16-tiktokcdn-com.akamaized.net',
                'log.tiktokv.com',
                'ib.tiktokv.com',
                'api-h2.tiktokv.com',
                'v16m.tiktokcdn.com',
                'api.tiktokv.com',
                'v19.tiktokcdn.com',
                'mon.musical.ly',
                'api2-16-h2.musical.ly',
                'api2.musical.ly',
                'log2.musical.ly',
                'api2-21-h2.musical.ly']}

        domains=(disneyPlusDomains,netflixDomains,youtubeDomains,tiktokDomains)

        for domain in domains: 
            add_dns_to_database(domain["parentDomain"],domain["subdomains"])
      
        #print("dns thread going to sleep for 10 seconds")
        # Sleep for 10 second between queries
        randomSleep = (60*stepBack)
        time.sleep(randomSleep)
        stepBack+=stepBack
        if stepBack>=512:
            stepBack=1


def add_dns_to_database(parentDomain, subdomains):
    for subdomain in subdomains:
        #pudb.set_trace()
        IPs = digIp(subdomain)
        for ip in IPs:
            if ip!='':
                db_add_dns_record(subdomain, ip,parentDomain)
                randomSleep = randint(3,20)
                time.sleep(randomSleep)
        else:
            logging.debug("skipped domain: " + subdomain + '\n\n\n')


def active_dns_setup():
    # Loop forever and beacon packets
    try:
        global dns_thread
        dns_thread = threading.Thread(
            target=update_dns,
            args=(),
            daemon=True,
        )
        return dns_thread
    except Exception as e:
        if hasattr(e,'message'):
            logging.warning(e.message)
        else:
            logging.warning(e)

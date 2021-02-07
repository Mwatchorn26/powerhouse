#
# Formerly based upon code from Patrick:
# https://www.padraig.io/arp-spoofer-1
#

import time
from scapy.all import *
from typing import List
import os
import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
import pudb
import logging
import keyboard

# Import the fuctions from my helper files. (yes, these should be classes)
from db_functions import *
import ip_tables as iptables
from discovery_thread import *
from arp_thread import *
from process_packet_thread import *
from active_dns_query_thread import *
from arp_wrangler import *
from network_tools import *

def Initialize(gateway_ip):
    create_db()
    if gateway_ip=='':
        gateways = db_select("device",['gateway',],[1,])
        if len(gateways)==0:
            myIp,_,_=my_ip_info()
            gateway_ip = router_guess(myIp)
    

    #Update the IPSET lists with any newly found IP ADDRESSES found for the 
    #various domains being searched.
    parentDomain_recordset=db_selectDistinct("dns_records",['parentDomain',])
    parentDomains = [x[0] for x in parentDomain_recordset]
    for parentDomain in parentDomains:
        iptables.load_ipset_list(parentDomain)



def main(target_ip: str, gateway_ip: str, interface: str, dns_ip: str):

    gateway_ip = Initialize(gateway_ip)
    #sys.exit(0)
    # pudb.set_trace()
    # Resolve the MAC addresses
    #hostnames=['youtube','videogoogle']
    resultset= db_select("dns_records",[],[])
    hostnames = [x[1] for x in resultset]
    iptables.set_iptables(interface)


    # Loop forever and beacon packets
    try:
        #SETUP THREADS:
        discovery_thread = discovery_thread_setup(interface)
        ###passive_dns_thread = passive_dns_setup(interface)
        ###arp_spoof_thread = arp_setup(interface, target_ip, target_mac, gateway_ip, gateway_mac)
        arp_wrangler_thread = arp_wrangler_setup(interface) #, target_ip, target_mac, gateway_ip, gateway_mac)
        #
        ##print("ARP thread started, moving on to Packet Processing Thread...")
        ##process_packet_thread = packet_processing_setup(interface, hostnames, dns_ip, attacker_mac, target_ip, target_mac)
        #active_dns_thread = active_dns_setup()

        #START THREADS
        #print("about to start discovery_thread.start")
        discovery_thread.start()
        #active_dns_thread.start()
        ###passive_dns_thread.start()
        ###arp_spoof_thread.start()
        arp_wrangler_thread.start()
        ##process_packet_thread.start()
        while True:



            # Check if b was pressed
            if keyboard.is_pressed('1'):
                pass

        discovery_thread_.join()
        ###arp_spoof_thread.join()
        #arp_wrangler_thread.join()
        ##process_packet_thread.join()
        #active_dns_thread.join()
        ###dns_thread.join()
        ###passive_dns_thread.join()

    except KeyboardInterrupt:
        print('Keyboard Interrupt')
        print('Returning IP Tables')
        iptables.return_iptables()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP", default='192.168.2.184')
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP", default="192.168.2.1")
    parser.add_argument(
        "-i",
        "--interface",
        dest="interface",
        help="Name of network interface",
        default="wlan0",
    )
    parser.add_argument("-d", "--dns-redirect", dest="dns_ip", help="DNS Redirect IP", default='10.10.10.10' )
    args = parser.parse_args()
    main(args.target, args.gateway, args.interface, args.dns_ip)

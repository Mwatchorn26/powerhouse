import time
from scapy.all import *
from typing import List
import os
import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
import pudb
from random import randint
import datetime

from arp_thread import *
import ip_tables
from network_tools import *
from db_functions import *


#I like the idea of using Worker Classes for threads
#See the second solution here: 
# https://stackoverflow.com/questions/23130399/python-threads-and-atomic-operations

def wrangler(interface):
    """
    wranger() starts up the various arp spoofing threads (one per MAC) as needed 
    based on the access rules.
    """
    threads=[]
    spoofedMacs=[]
    restricted_macs=[]
    #target_mac = resolve_ip("target", target_ip)
    gateways = db_select("device",['gateway',],[1,])
    if len(gateways)==1:
        gateway_mac = gateways[0][1]
        gateway_ip = gateways[0][2]
    else:
        return -1
    #gateway_mac = resolve_ip("gateway", gateway_ip)
    
    attacker_mac = get_attacker_mac(interface)
    #global spoofed_macs=[]
    previously_restricted_macs=[]

    while True:                                 #Never get tired in the saddle, keep wrangling.
        #print('Running wrangler() in thread')

        ##get access rules from DB
        #rules=db_select('access',[],[])

        ##find rules that apply right now
        #
        ##filter for day
        #todays_lucky_number=datetime.datetime.today().weekday() #0=Monday, 1=Tuesday... 6=Sunday
        ##print(todays_lucky_number)
        #rules = [rule for rule in rules if rule[3]==None or rule[3]=='' or str(todays_lucky_number) in str(rule[3])] #cheating because we only can get the numbers [0,1,2,3,4,5,6], no double digit numbers, YES!
        #
        #hour_now = str(datetime.datetime.now().hour).zfill(2)
        #minute_now = str(datetime.datetime.now().minute).zfill(2)
        #time_now = hour_now + ":" + minute_now
        ##print(time_now)
        ##pudb.set_trace()
        ##filter for now after start time
        #rules= [rule for rule in rules if rule[1]==None or rule[1]=='' or rule[1]<=time_now ]
        #
        ##filter for now before stop time
        #rules= [rule for rule in rules if rule[2]==None or rule[2]=='' or rule[2]>time_now]
       
        rules = iptables.active_rules()

        #Isolate for the user IDs from the list of rules that are left
        user_ids = [rule[4] for rule in rules if rule[4]!=None]
       
        #find MAC addresses for users who are impacted
        devices=db_selectFromList("device",'user_id',user_ids)
        restricted_macs=[row[1] for row in devices]
        #pudb.set_trace()
        #Start 
        
        #print("restriced_macs")
        #print(*restricted_macs, sep=",")
        #print("spoofedMacs")
        #print(*spoofedMacs, sep=",")
        newSpoofedMac=False #Flag variable to allow us to print the rules once at the end of each update (newly added rule)
        
        for mac in restricted_macs:
            if mac not in spoofedMacs:
                try:
                    logging.info("in adding new mac: " + mac)
                    mac_rules = iptables.active_rules_for_mac(rules, mac)
                    #print_rules(rules)
                    action=''
                    for rule in mac_rules:
                        if (rule[5]==1) or (action=='DROP_ALL'):
                            action='DROP_ALL'
                        else:
                            action='FILTER'
                    target_device = db_select("device",['mac_addr',],[mac,])[0]
                    target_ip = target_device[2]
                    target_mac = mac
                    spoofedMacs.append(mac) #thread will remove it's mac when it stops.
                    new_arp_thread = threading.Thread(target=arp_worker, args=(interface, target_ip, target_mac, gateway_ip, gateway_mac, spoofedMacs, action), daemon=True)
                    threads.append(new_arp_thread)
                    new_arp_thread.start()
                    newSpoofedMac=True
                except Exception as e:
                    if hasattr(e,'message'):
                        print(e.message)
                    else:
                        print(e)
            elif newSpoofedMac:
                logging.info("in elif newSpoofedMac")
                #No New Spoofed Macs
                print_rules(rules)
                newSpoofedMac=False
            elif len(restricted_macs)!=len(previously_restricted_macs):
                logging.info("in elif restricted_macs <> prev_restricted_macs")
                print_rules(rules)
                previously_restricted_macs = restricted_macs
            else:
                previously_restricted_macs = restricted_macs
        #for mac in spoofedMacs:
        #    if mac not in restricted_macs:
        #        try:
        spoofedMacs=restricted_macs #No need to explicitly remove items from spoofedMacs, just overwrite it with the new list (aka restriced_macs)
        time.sleep(5)

def print_rules(rules):
    for rule in rules:
        print(f"ID: {rule[0]}   user_id:{rule[4]}")

def arp_wrangler_setup(interface):
    try:
        global wrangler_thread
        wrangler_thread = threading.Thread(
            target=wrangler,
            args=(interface,),
            daemon=True,
        )
        return wrangler_thread
    except Exception as e:
        if hasattr(e,'message'):
            print(e.message)
        else:
            print(e)

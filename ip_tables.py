import os
from db_functions import *
import logging
import datetime

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
#logger = logging.getLogger(__name__)


#LIST IPTABLES WITH LINE NUMBERS
#---------------------------------------v
#sudo iptables -t filter -L FORWARD --line-numbers -n -v

#INSERT NEW RULE AT A SPECIFIC POINT:
#--------------v-----v----v
#sudo iptables -I FORWARD 1 -m state -s 192.168.2.0/24 -d


#Log IPTABLE FORWARDED PACKETS:
#sudo iptables -I FORWARD 1 -j LOG

#THEN to see what's happening:
#tail -f /var/log/messages

#CLEAR the log
#sudo truncate -s0 /var/log/messages

"""
#     I P S E T    C H E A T S H E E T

https://wiki.archlinux.org/index.php/Ipset

# List all ipsets:
# sudo ipset list

# List specifics for named ipset
# sudo ipset list name-of-ipset

# Flush ALL ipsets:
# sudo ipset destroy


# Add an IP address to a set:
# sudo ipset add name-of-ipset ip-address

"""



def load_ipset_list(parentDomain):
    ipset_cmd(f"ipset create {parentDomain} hash:net -exist")
    parent_records = db_select("dns_records",['parentDomain',],[parentDomain,])
    for record in parent_records:
        ipset_cmd(f"ipset add {parentDomain} {record[2]} > /dev/null 2>&1")

def ipset_cmd(cmd):
        logging.debug(cmd)
        os.system(cmd)

def apply_access_rules():
    #users = db_select(.....)
    users=[]
    for user in users:
        assign_access_rule(user)

def assign_access_rule(user):
    pass

def set_iptables(interface):
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    #os.system(
        ##f"iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1 -i {interface}"
        ##f"iptables -t nat -A PREROUTING  -j NFQUEUE --queue-num 1 -i {interface}"
        ##f"iptables -A PREROUTING  -j NFQUEUE --queue-num 1 -i {interface}"

        # ----->  U S E   T H I S  O N E    S E E   A L L  <---------
        #f"iptables -I FORWARD  -j NFQUEUE --queue-num 1 -i {interface}"


        #f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1 -i {interface}"
    #)

    #iptables -v -I INPUT -m set --match-set blacklist src -j DROP
    #iptables -v -I PREROUTING -m set --match-set Emma dest -j DROP
    #iptables -v -I PREROUTING -m set --match-set Ali dest -j DROP
    #iptables -v -I PREROUTING -m set --match-set Ben dest -j DROP
 
    # W O R K I N G (ISOLATED FOR DAD'S PHONE)
    os.system("ipset create Dad hash:ip -exist")
    os.system("ipset add Dad 192.168.2.184 -exist") 
    #os.system("iptables -v -I FORWARD -m set --match-set Dad dst -j DROP")

    #TESTING WITHOUT THESE "REQUIRED FORWARDS" FOR UBUNTU 16
    #os.system(f"iptables -A FORWARD -o {interface} -j ACCEPT")
    #os.system(f"iptables -A FORWARD -m state --state ESTABLISHED,RELATED -i {interface} -j ACCEPT")


    #os.system(f"iplist_data=$(cat ../IPs/YouTube/youtube_ips.txt)")
    #os.system(f"ipset create ipset_youtube_list hash:net -exist")
    #os.system(f"for row_data in $iplist_data; do ipset add ipset_youtube_list ${row_data}; done")



    #os.system(f"mapfile -t myArray < ../IPs/YouTube/youtube_ips.txt")

    #WORKING, WRITE CODE TO CHECK IF ipset_youtube_list exists, IF NOT RUN THIS:
    #os.system(f'while IFS= read -r line; do sudo ipset add ipset_youtube_list "$line"; done < ../IPs/YouTube/youtube_ips.txt') 


    #fwd_chain = " iptables -v -I FORWARD "
    #Dad_src = " -s 192.168.2.184 "
    #youtube_set_dst = " -m set --match-set Youtube dst " 
    #Dad_dst = " -d 192.168.2.184 "
    #youtube_set_src = " -m set --match-set Youtube src " 
    ##os.system("iptables -v -I FORWARD -m set --match-set ipset_youtube_list dst -j DROP")
    ##os.system("iptables -v -I FORWARD -m set --match-set Dad src ipset_youtube_list dst -j DROP")
    #os.system(fwd_chain + Dad_src + youtube_set_dst + " -j DROP")
    #os.system(fwd_chain + Dad_dst + youtube_set_src + " -j DROP")


def create_rule(user_ip, ipset_name,action):
    try:
        #pudb.set_trace()
        if action=='FILTER':
            #if True:
            fwd_chain = " iptables -v -I FORWARD "
            user_src_ip = f" -s {user_ip} "
            ipset_dst = f" -m set --match-set {ipset_name} dst " 
            user_dst_ip = f" -d {user_ip} "
            ipset_src = f" -m set --match-set {ipset_name} src " 
            os.system(fwd_chain + user_src_ip + ipset_dst + " -j DROP")
            os.system(fwd_chain + user_dst_ip + ipset_src + " -j DROP")
            #os.system("iptables -v -I FORWARD -m set --match-set ipset_youtube_list dst -j DROP")
            #os.system("iptables -v -I FORWARD -m set --match-set Dad src ipset_youtube_list dst -j DROP")
        #elif rule_type=='drop_all':
        elif action=='DROP_ALL':
            fwd_chain = " iptables -v -I FORWARD "
            user_src_ip = f" -s {user_ip} "
            user_dst_ip = f" -d {user_ip} "
            os.system(fwd_chain + user_src_ip + " -j DROP")
            os.system(fwd_chain + user_dst_ip + " -j DROP")
        else:
            logging.info(f"IPTABLES Rule not properly defined: {user_ip} {ipset_name} {rule_type}")
    except Exception as e:
        if hasattr(e,'message'):
            print(e.message)
        else:
            print(e)

def delete_rule(user_ip, ipset_name,action):
    try:
        if action=='DROP_ALL':
            fwd_chain = " iptables -D FORWARD "
            user_src_ip = f" -s {user_ip} "
            ipset_dst = f" -m set --match-set {ipset_name} dst " 
            user_dst_ip = f" -d {user_ip} "
            ipset_src = f" -m set --match-set {ipset_name} src " 
            os.system(fwd_chain + user_src_ip + ipset_dst + " -j DROP")
            os.system(fwd_chain + user_dst_ip + ipset_src + " -j DROP")
        elif action=='FILTER':
            fwd_chain = " iptables -D FORWARD "
            user_src_ip = f" -s {user_ip} "
            user_dst_ip = f" -d {user_ip} "
            os.system(fwd_chain + user_src_ip + " -j DROP")
            os.system(fwd_chain + user_dst_ip + " -j DROP")
    except Exception as e:
        if hasattr(e,'message'):
            print(e.message)
        else:
            print(e)

# HOW TO GET YOUTUBE RANGES OF IP ADDRESSES:
#https://stackoverflow.com/questions/9342782/is-there-a-way-to-get-all-ip-addresses-of-youtube-to-block-it-with-windows-firew#19385835

#The way to find all the IP addresses associated with a URL is first to find the AS Number, you can get it in http://networktools.nl/asinfo/ For YouTube get it in http://networktools.nl/asinfo/youtube.com There you get the AS Number
#
#Primary ASN : 15169
#
#Now, type in terminal:
#
# whois -h whois.radb.net -- '-i origin AS15169' | grep ^route: > youtube_ips.txt

#Remove useless characters
##sed -i 's/search_string/replace_string/' filename
#sed -i 's/route:      //' filename

#Remove leading and trailing white space
#cat testtube4 | awk '{$1=$1};1'

def myMapFunc(n):
    resized = '{0:0>2}'.format(str(len(n)))
    return "|" + resized + '|' + n

def block_dns(src_ip_str:str, domain: str):
    domain_array = domain.split('.')
    extended_domain = str(''.join(map(myMapFunc, domain_array))) + "|"
    #iptable_cmd = 'sudo iptables -I FORWARD -p udp -dport 53 -m string --hex-string "' + extended_domain + '" -algo bm -j DROP'
    ##print(iptable_cmd)
    ##https://defragged.org/2020/05/20/tips-and-tricks-blocking-dns-requests-via-iptables/
    ##print('iptables -I INPUT -p udp –dport 53 -m string –hex-string “|03|www|07|example|03|com|” –algo bm -j DROP')
    ##os.system(iptables -I INPUT -p udp –dport 53 -m string –hex-string “|03|www|07|example|03|com|” –algo bm -j DROP
    #https://unix.stackexchange.com/questions/245763/iptables-hex-string-block-dns-query
    #iptable_cmd = 'sudo -A FORWARD -s 192.168.2.184/32 -p udp -m udp --dport 53 -m u32 --u32 "0x1c&0xf8=0x0" -m string --hex-string "|03777777076578616d706c6503636f6d|" --algo bm --from 40 --to 65535 -j DROP'
    iptable_cmd = 'sudo -A FORWARD -s '+src_ip_str+'/32 -p udp -m udp --dport 53 -m u32 --u32 "0x1c&0xf8=0x0" -m string --hex-string "' + extended_domain + '" --algo bm --from 40 --to 65535 -j DROP'
    print(iptable_cmd)
    os.system(iptable_cmd)

def return_iptables():
    os.system("sysctl -w net.ipv4.ip_forward=0")
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -X")



def all_rules():
        rules=db_select('access',[],[])
        return rules

def active_rules():
    rules = all_rules()
    #find rules that apply right now
        
    #filter for day
    todays_lucky_number=datetime.datetime.today().weekday() #0=Monday, 1=Tuesday... 6=Sunday
    #print(todays_lucky_number)
    todays_rules = [rule for rule in rules if rule[3]==None or rule[3]=='' or str(todays_lucky_number) in str(rule[3])] #cheating because we only can get the numbers [0,1,2,3,4,5,6], no double digit numbers, YES!
        
    hour_now = str(datetime.datetime.now().hour).zfill(2)
    minute_now = str(datetime.datetime.now().minute).zfill(2)
    time_now = hour_now + ":" + minute_now
    #print(time_now)
    #pudb.set_trace()
    #filter for now after start time
    active_rules = [rule for rule in todays_rules if rule[1]==None or rule[1]=='' or rule[1]<=time_now ]
    
    #filter for now before stop time
    active_rules = [rule for rule in active_rules if rule[2]==None or rule[2]=='' or rule[2]>time_now]
    return active_rules

    ##Isolate for the user IDs from the list of rules that are left
    #user_ids = [rule[4] for rule in rules if rule[4]!=None]
    
    ##find MAC addresses for users who are impacted
    #devices=db_selectFromList("device",'user_id',user_ids)
    #restricted_macs=[row[1] for row in devices]

def active_rules_for_mac(active_rules, mac):
    #pudb.set_trace()
    all_devices = db_select('device',[],[])
    user_ids = [device[4] for device in all_devices if device[1]==mac]
    if len(user_ids)!=1:
        logging.error("1 and only 1 user id should have been returned for mac " + mac)
        print(*user_ids, sep=',')
        return ""
    user_id = user_ids[0]
    mac_rules = [ rule for rule in active_rules if rule[4] == user_id]
    print(*mac_rules, sep=',')
    return mac_rules

def active_rules_for_user(active_rules, user_id):
    #pudb.set_trace()
    user_rules = [rule for rule in active_rules if rule[4]==user_id]
    print(*user_rules, sep=',')
    return user_rules

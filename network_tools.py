import os
import subprocess
import pudb
import logging


logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
#logger = logging.getLogger(__name__)


def my_ip_info():
    #os.system(ip -o -f inet addr show | awk '/scope global/ {print $4}')
    #ps = subprocess.Popen(('ps', '-A'), stdout=subprocess.PIPE)
    #output = subprocess.check_output(('grep', 'process_name'), stdin=ps.stdout)
    #ps.wait()
    ps = subprocess.Popen(('ip', '-o', '-f', 'inet', 'addr', 'show'), stdout=subprocess.PIPE)
    ps.wait()
    output = subprocess.check_output(('awk', '/scope global/ {print $4}'), stdin=ps.stdout)
    string_output = output.decode('utf-8')
    ip_mask_array = string_output.split('/')
    ip_array = ip_mask_array[0].split('.')

    ip  = '.'.join(ip_array)
    subnet = '.'.join(ip_array[:3]) + ".0"
    mask = ip_mask_array[1].replace('\n','')
    return ip, subnet, mask


def router_guess(my_ip):
    """
    Assume 24 bit mask.
    Swap the last octect of my IP with "1", as that's the most common IP address for a home router.
    """
    ip_array = my_ip.split('.')
    return '.'.join(ip_array[:3]) + ".1"


def digIp(domain: str):
    try:
        r1 = subprocess.check_output(["dig", domain])
        logging.debug("r1:\n"+r1.decode("utf-8")+"\n\n")
        ANSWER_SECTION = r1.decode("utf-8").split(";; ANSWER SECTION:")
        #pudb.set_trace()
        if len(ANSWER_SECTION)==1:
            logging.debug("ERROR no part 2 in ANSWER SECTION:")
            logging.debug(r1.decode("utf-8"))
        logging.debug("ANSWER_SECTION:\n"+ANSWER_SECTION[1]+"\n\n")
        rows = ANSWER_SECTION[1].split("\n")
        logging.debug("rows:\n")
        rows
        logging.debug("\n")
        IPs = [row.split("IN\tA\t")[1] for row in rows if "IN\tA\t" in row]
        logging.debug("IPs:\n")
        IPs
        logging.debug("\n") 
                
        #r2 = r1.decode("utf-8").split('IN\tA\t')
        #ip = r2[1].split('\n')[0]
        #print(ip)
        return IPs
    except Exception as e:
        logging.warning("\n\n\nPROBLEM WITH DOMAIN: " + str(domain))
        if hasattr(e,'message'):
            logging.error("Error Msg: " + e.message)
        else:
            logging.error(e)
        return ''
        

def nmap_devices():
    #nmap -sn 192.168.2.0/24
    ip, subnet, mask = my_ip_info()
    f = open("nmap_results","w")
    logging.info("test: nmap -sn " + str(subnet + "/" + mask))
    subprocess.call(["nmap","-sn",str(subnet + "/" + mask)], stdout=f)

def manufacturer(mac:str):
    """
    Return Name of Manufacturer of device with said MAC address.
    """
    # Read out the file
    ps = subprocess.Popen(('cat','manuf.txt'), stdout=subprocess.PIPE)
    ps.wait()
    logging.debug('{}'.format(ps.communicate()[0]))
    # Pipe the list from the file to a grep command to search for 
    # the first 8 characters "aa:bb:cc" of the mac address
    ps2 = subprocess.Popen(('grep',mac[:8]),stdin=ps.stdout, stdout=subprocess.PIPE)
    ps2.wait()
    logging.debug('{}'.format(ps2.communicate()[0]))
    
    #Pipe the matching line of the file, to awk to grab the 2nd work (the Manufacturer's common name) 
    manufacturer = subprocess.check_output(('awk',"'{print $2}'"), stdin=ps2.stdout)

    #Return the common name of the Manufacturer
    return manufacturer

def get_attacker_mac(interface):
    try:
        return get_if_hwaddr(interface)
    except:
        return None

def get_mac_from_ip(ip_address: str):
    # dst="ff:ff:ff:ff:ff:ff" broadcasts the request to the whole network
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(pdst=ip_address, hwdst="ff:ff:ff:ff:ff:ff"),
        timeout=2,
        verbose=0,
    )
    if ans:
        return ans.hwsrc
    else:
        return None

def resolve_ip(name: str, ip_address: str):
    logging.debug(f"Resolving MAC address for {name} {ip_address}")
    # Resolve the target's MAC address
    mac = get_mac_from_ip(ip_address)
    if mac == None:
        logging.debug(f"Unable to resolve IP address. Exiting!")
        sys.exit(0)
    logging.debug(f"Resolved to {mac}")
    return mac

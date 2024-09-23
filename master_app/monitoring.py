import time
from scapy.all import *
from django.conf import settings
from .models import *


from .utils import (
    ETHERNET_IP_VERSION_TYPE
)


from collections import defaultdict



def decode_string(payload):
    try:
        # return bytes(strisng).decode('unicode-escape',errors='ignore')
        s1 = payload.decode('unicode-escape', "strict")
        s2 = s1.encode('latin-1', "strict")
        s3 = s2.decode('utf-8', "strict")
        
        # print(s3)
        # print(payload)s
        return s3
        # return bytes(string).decode('unicode-escape')
    # except UnicodeDecodeError as e:
    #     # print(e)
    #     return None
    # except AttributeError as e:
    #     return None
    except:
        return None

def get_ethernet_type(packet):
    try:
        return ETHERNET_IP_VERSION_TYPE.get(str(packet.type  or  ''), "Unknown")
    except Exception as e:
        # print(e)
        return None

def collect_packets():

    timeout_seconds = 0.1
    start_time = time.time()
    captured_packets = []

    while time.time() - start_time < timeout_seconds:
        c = sniff( iface=settings.NETWORK_INTERFACE_LABEL, timeout=1)
        # print(c.summary())
        # if c is not None:
        for packet in c:
            # Process each packet in the captured_packets list
            # print(packet.summary(), "*****")
            # print(read_payload(packet.payloafd))
            # print(read_payload_v2(packet))
            captured_packets.append(packet)
            # pass

        # print(c)
        # captured_packets.append(sniff(prn=packet_callback, store=0, filter="tcp", count=1))
    # captured_packet = sniff(prn=packet_callback, store=0, filter="tcp", count=0)
    # for cp in captured_packet:
    #     print("----------------")
    #     print(packet_callback(cp))
    #     print("----------------")
    # result = packet_callback(captured_packet)
    # print(captured_packets)
    # print("Finished running")
    return captured_packets



# Get Protocol Name by number
def proto_name_by_num(packet):
    try:
        for name,num in vars(socket).items():
            if name.startswith("IPPROTO") and packet.proto == num:
                return name[8:]
        return None
    except Exception as e:
        # print(e)
        return None
    
# Get Packet Source Port
    
def get_packet_src_port(packet):
    try:
        return packet.sport
    except Exception as e:
        # print(e)
        return None
    

def get_packet_dst_port(packet):
    try:
        return packet.dport
    except Exception as e:
        # print(e)
        return None
    


def read_payload(packet):
    try:

        # return str(packet.load, 'latin-1', errors="replace").replace("\x00", ".")
        # return bytes(packet[TCP].payload).decode('UTF8','ignore')
        # payload = ""
        if Raw in packet:
                # payload = 
                # print(bytes(packet[Raw].load).decode('UTF8',errors='ignore'))
                # x = bytes(packet[Raw].load).decode('UTF8',errors='ignore')
                # x = str(x , "utf-8")

                # print(type(x))
                # x = bytes(bytes(packet[Raw].load).decode('UTF8',errors='ignore'), 'UTF8')
                # print(bytes(bytes(packet[Raw].load).decode('UTF8',errors='ignore'), 'utf-8').decode('utf-8', errors='ignore'))
                # return bytes(bytes(packet[Raw].c).decode('UTF8',errors='ignore'), 'UTF8').decode('UTF8', errors='ignore')
                # print(packet[Raw].load)
                # x = bytes(packet[Raw].load).decode('ascii',errors='ignore')
                # x = decode_string(packet[Raw].load)
                # x = x.encode('UTF8', 'ignore')
                # x = bytes(x).decode('UTF8', 'ignore')
                # print(x)
                # return x
                # return decode_string(packet[Raw].load)
                load = decode_string(packet[Raw].load)
                if load is not None:
                    if "nmap" in load.lower():
                        return (load, "NMAP")
                    else:
                        return (load, None)
                else:
                    return (load, None)
# OPTIONS / HTTP/1.1
# Connection: close
# User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
# Host: 192.168.0.143:8000


        if TCP in packet:
                # return bytes(bytes(packet[TCP].load).decode('UTF8',errors='ignore'), 'UTF8').decode('UTF8', errors='ignore')
                # return bytes(packet[TCP].payload).decode('UTF8',errors='ignore')
                # return bytes(packet[TCP].payload).decode('UTF8',errors='ignore')
                # print(packet[TCP].load)
                # x = bytes(packet[TCP].payload).decode('ascii',errors='ignore')
                # # x = bytes(x, 'utf-8').decode('utf-8', 'ignore')
                # # x = x.encode('UTF8', 'ignore')
                # # x = bytes(x).decode('UTF8', 'ignore')
                # print(x)
                # return x
                # return decode_string(packet[TCP].payload)  
                payload = decode_string(packet[TCP].payload)  
                if payload is not None:
                    if "nmap" in payload.lower():
                        return (payload, "NMAP")
                    else:
                        return (payload, None)
                else:
                    return (payload, None)

        # payload = 
        # if "nmap" in payload:
        #     print(payload)
                # print(payload)
    # except UnicodeDecodeError as e:
    #     print(e)
    #     pass
    # except AttributeError as e:
    #     print(e)
    #     pass
    except :
        
        traceback.print_exc()
    return (None, ":Error")





def get_packet_dst_ip(packet):
    try:
        return packet[IP].dst
    except Exception as e:
        return None
    


def get_packet_src_ip(packet):
    try:
        return packet[IP].src
    except Exception as e:
        return None

def save_packets(result):
    # Create and save the model instance
    if result is not None:
        for packet in result:
            x = read_payload(packet)
            # print(x)
            if x is not None:
                if not x.isspace():
                    Packets.objects.create(
                        destination_ip=get_packet_dst_ip(packet),   
                        source_ip=get_packet_src_ip(packet),
                        type=get_ethernet_type(packet),
                        protocol= proto_name_by_num(packet),
                        src_port= get_packet_src_port(packet),
                        dst_port= get_packet_dst_port(packet),
                        payload=x,
                    )
    return None


# saved packets received from API
def save_packets_api(result):
    # Create and save the model instance
    if result is not None:
        for packet in result:
            # x = read_payload(packet[-1])
            x = packet[-1]
            if x is not None:
                if not x.isspace():
                    Packets.objects.create(
                        destination_ip=get_packet_dst_ip(packet[0]),   
                        source_ip=get_packet_src_ip(packet[1]),
                        type=get_ethernet_type(packet[2]),
                        protocol= proto_name_by_num(packet[3]),
                        src_port= get_packet_src_port(packet[4]),
                        dst_port= get_packet_dst_port(packet[5]),
                        payload=x,
                    )
    return None





# Get Packet List from Capture Packets
PORT_SCANNING_MINIMUM_THRESHOLD = 30
def get_packet_list(result):
    counts = defaultdict(int)
    packet_list = []
    # [(packet[IP].dst, packet[IP].src, read_payload(packet)) for packet in result]
    # total = 0
    dictA = {
        "dst_port" : []
    }
    for packet in result:
        if IP in packet:
            try:
                source = packet[IP].src
                destination = packet[IP].dst
                dst_port = packet[IP].dport
                counts[(source, destination)] += 1
                counts[(destination, dst_port )] += 1
                if dst_port not in dictA["dst_port"]:
                    dictA["dst_port"].append(dst_port)
                
                # counts["dst_port"] = counts[dst_port]+1
                # total = total+1
                # calculate total number of ports
            # except KeyError:
            #     dictA["dst_port"] = []
            #     dictA["dst_port"].append(packet[IP].dport)
            except:
                # traceback.print_exc()
                pass

        # print("Total Dst Ports : ", total)
        payload, type_tool = read_payload(packet)
        # print(payload)
        # if payload is not None :
        #     # payload = payload.strip().replace("\n", "").replace("\r", "")
        #     # print(payload, end="***")
        #     # if not x != "*-1\r\n":
        #     if(len(dictA["dst_port"]) > PORT_SCANNING_MINIMUM_THRESHOLD):
        #         type_tool = "PortScanning"
        #         payload = "Port Scanning"
        #     if len(payload) > 5:
        #         if not payload.isspace():
        #             packet_list.append((
        #                 {
        #                     "dst_ip" : get_packet_dst_ip(packet),
        #                     "payload" : payload,
        #                     "src_ip" : get_packet_src_ip(packet),
        #                     "src_port" : get_packet_src_port(packet),
        #                     "dst_port" : get_packet_dst_port(packet),
        #                     "type_tool" : type_tool
        #                     # "type" : get_ethernet_type(packet),
        #                     # "protocol" : proto_name_by_num(packet),
        #                 }
        #                 # get_packet_src_ip(packet),
        #                 # get_packet_src_port(packet),
        #                 # get_packet_dst_port(packet),
        #                 # x,
        #             ))
    # if payload is not None :
            # payload = payload.strip().replace("\n", "").replace("\r", "")
            # print(payload, end="***")
            # if not x != "*-1\r\n":
    payload = ""
    if(len(dictA["dst_port"]) > PORT_SCANNING_MINIMUM_THRESHOLD):
        type_tool = "PortScanning"
        payload = "Port Scanning"
    if len(payload) > 5:
        if not payload.isspace():
            packet_list.append((
                {
                    "dst_ip" : get_packet_dst_ip(packet),
                    "payload" : payload,
                    "src_ip" : get_packet_src_ip(packet),
                    "src_port" : get_packet_src_port(packet),
                    "dst_port" : get_packet_dst_port(packet),
                    "type_tool" : type_tool
                    # "type" : get_ethernet_type(packet),
                    # "protocol" : proto_name_by_num(packet),
                }
                # get_packet_src_ip(packet),
                # get_packet_src_port(packet),
                # get_packet_dst_port(packet),
                # x,
            ))
    print(dict(counts))
    print(len(dictA["dst_port"]), dictA["dst_port"])
    return packet_list


def packet_callback(packet):
    # print(type(packet))
    # print(packet.show())
    try:
        if packet.haslayer(TCP):
            # print(packet[IP])
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            packet_data = {
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "port_src": port_src,
                "port_dst": port_dst,
            }
            # print("...")
            return packet_data
        else:
            return None
    except Exception as e:
        print("Error")
        print(e)
        # print(packet)
        return None

from scapy.all import *
import traceback
import base64
import json

ETHERNET_IP_VERSION_TYPE= {
    "2048" : "IPv4",
}
from collections import defaultdict



def decode_string(payload):
    # s1 = payload.decode('unicode-escape', "ignore")
    # s2 = s1.encode('latin-1', "ignore")
    # s3 = payload.decode('unicode-escape', "ignore").encode('latin-1', "ignore").decode('UTF8', "ignore")
    # return s3
    return payload.decode('unicode-escape', "ignore").encode('latin-1', "ignore").decode('UTF8', "ignore")



def read_payload(packet):
    try:
        if Raw in packet:
            return decode_string(packet[Raw].load)
        if TCP in packet:
            return decode_string(packet[TCP].payload)
        
        
    except AttributeError as e:
        pass
    except :
        traceback.print_exc()
    return None

def packet_callback(packet):
    if TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        seq_number = packet[TCP].seq
        ack_number = packet[TCP].ack
        payload = packet[TCP].payload.load.decode('utf-8', errors='ignore')

        # Check if it's the first packet in the stream
        if 'TCP_Stream' not in packet:
            packet['TCP_Stream'] = {'client': '', 'server': ''}

        # Determine if the packet is going from the client to the server or vice versa
        direction = 'client' if ip_src == '192.168.14.191' and tcp_sport == client_port else 'server'

        # Update the TCP stream for the appropriate direction
        packet['TCP_Stream'][direction] += payload

        print(f"{direction.capitalize()} to {ip_dst}:{tcp_dport} (Seq: {seq_number}, Ack: {ack_number}):")
        print(payload)
        print('-' * 50)

def get_tcp_stream_details(packet):
    # print(packet)
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport

            # Check if the packet is part of a TCP stream
            if TCP in packet:
                # Extract relevant TCP information
                seq_number = packet[TCP].seq
                ack_number = packet[TCP].ack
                payload = read_payload(packet)

                # Print TCP stream details
                print(f"Source IP: {ip_src}, Source Port: {tcp_sport}")
                print(f"Destination IP: {ip_dst}, Destination Port: {tcp_dport}")
                print(f"Sequence Number: {seq_number}")
                print(f"Acknowledgment Number: {ack_number}")
                print("Payload:")
                print(payload)
                print('-' * 50)
    except AttributeError as e:
        print(e)
    except Exception as e:
        print(e)


# database define network pkts
def network_conversation(pkt):
    # b = raw(base64.b64decode("eKxEEF7rhDmPjTx6CABFAAA0WsBAAH8GxIusEAsFrKV4vdBVABbrPYjiAAAAAIAC+vBTGwAAAgQFtAEDAwgBAQQC"))
    # c = Ether(b)/IP(b)/TCP(b)
    
    # get_tcp_stream_details(c)
    # packet_callback(c)
    try:
        protocol = pkt.protocol
        source_address = pkt.source_ip
        source_port = pkt.src_port
        destination_address = pkt.destination_ip
        destination_port = pkt.dst_port
        payload = pkt.payload
        timestamp = pkt.timestamp
        return  (protocol,  source_address, source_port, destination_address, destination_port, payload, timestamp)
    except AttributeError as e:
        pass

# 
def read_list(lst):
    for item in lst:
        # 
        yield network_conversation(item)




# read json file
def read_json(filename):
    with open(filename) as f:
        data = json.load(f)
        return data


# read values for a specific key inside json file
def read_json_key(filename, team_id):
    data = read_json(filename)
    try:
        # search json based on team id
        for team in data:
            if(int(team["id"]) == int(team_id)):
                return team
            # print(team.items())
            # print(team["id"])
            # for key, value in team.items():
            #     # print(value == team_id)
            #     print(value, team_id)
            #     if value == team_id:
            #         return value

    except:
        traceback.print_exc()
        return None



# read big file chunks by chunks
def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


# get common src and dst ip addresses
# filename : pcap file
def get_common_ip_addresses(TextIOWrapper, ip_address=None):
    # print(filename)
    if TextIOWrapper is None or ip_address is None:
        print("filename or ip_address information is missing")
        return None
    else:
        # print(TextIOWrapper.name)
        A = {}
        with open(TextIOWrapper.name) as f:
            # for piece in read_in_chunks(f):
            #     # process_data(piece)

            #     print(piece)
            #     print("-"*70)
            for line in f:
                # process_data(line)
                # print(line.split("|"))
                src, dst = line.replace("\n","").split("|")
                # print(src, dst)
                if dst is not None:
                    try:
                        if dst not in A[str(src)]:
                            A[src].append(dst)
                            # print(A.keys())
                            # if not src in A[str(src)]:
                    except KeyError:
                        A[src] = []
                        A[src].append(dst)
                    except AttributeError as e:
                        # print(e)
                        pass
                    except :
                        traceback.print_exc()

        return A[str(ip_address)]
        # print(A)
        # try:
        #     for key, value in A.items():
        #         print(key)
        #         # A.pop(key)
        #         # del A[key]
        #         # for i in value:
        #         #     if i in A.keys():
                        
        #             # del A[key]
        #         # for i in value:
        #         #     # print(i)
        #         #     print(A[i])
        #             # if i in A[i]:
        #             #     A.pop(key)
        #         # print(key, value)
        # except :
        #     pass
        # print(A)
        # return A


# READ MAC ADDRESS from text file
def read_mac_address(TextIOWrapper, ip_address=None):
    if TextIOWrapper is None or ip_address is None:
        print("filename or ip_address information is missing")
        return None
    else:
        # print(TextIOWrapper.name)
        A = {}
        with open(TextIOWrapper.name) as f:
            for line in f:
                # process_data(line)
                # print(line.split("|"))
                src_mac,src_vendror, src_ip, dst_mac, dst_vendor, dst_ip = line.replace("\n","").split("|")
                # print(src_mac,src_ip, dst_mac, dst_ip)
                if dst_ip is not None:
                    try:
                        if dst_ip not in A[str(src_ip)].keys():
                            A[src_ip][dst_ip] = {
                                "ip" : dst_ip,
                                "mac" : dst_mac,
                                "dst_vendor": dst_vendor
                            }
                    except KeyError:
                        A[src_ip] = {
                            str(dst_ip) : {
                                "ip" : dst_ip,
                                "mac" : dst_mac
                            }
                        }
                    except AttributeError as e:
                        pass
                    except :
                        traceback.print_exc()
                    # try:
                    #     if dst_ip not in A[str(src_ip)]:
                    #         A[src_ip].append(dst_ip)
                    #         # print(dst_mac)
                    #         # print(A.keys())
                    #         # if not src_ip in A[str(src_ip)]:
                    # except KeyError:
                    #     A[src_ip] = []
                    #     A[src_ip].append(dst_ip)
                    # except AttributeError as e:
                    #     # print(e)
                    #     pass
                    # except :
                    #     traceback.print_exc()

        return A[str(ip_address)]
        # return A


def detect_tool(tool_name):
    # print(tool_name)
    # match nmap in a string

    if re.search("sqlmap",tool_name, re.IGNORECASE):
        return "{} Detected".format("sqlmap".upper())
    elif re.search("nmap",tool_name, re.IGNORECASE):
        return "{} Detected".format("nmap".upper())
    elif re.search("dirbuster",tool_name, re.IGNORECASE):
        return "{} Detected".format("DirBuster".upper())
    else:
        return tool_name



def get_user_agents(TextIOWrapper, ip_address=None):
    if TextIOWrapper is None or ip_address is None:
        print("filename or ip_address information is missing")
        return None
    else:
        tool_list = []
        keys_list = ["src_ip", "dst_ip", "tool"]
        with open(TextIOWrapper.name) as f:
            tool_list = [dict(zip(keys_list, list(map(lambda x: detect_tool(x), [x for x in line.replace("\n","").split("|")])) )) for line in f]
        
        # print(tool_list.count("nmap"))
        return tool_list
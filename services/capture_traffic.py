import json
import time
from scapy.all import *
from decouple import config
import requests
import psycopg2
import uuid
from datetime import datetime, timezone
import traceback
import os
import monitor_service
import asyncio
from pathlib import Path
import base64
from datetime import date



# p0f


from pyp0f.database import DATABASE
from pyp0f.exceptions import PacketError
from pyp0f.fingerprint import fingerprint_http, fingerprint_mtu, fingerprint_tcp
from pyp0f.net.layers.tcp import TCPFlag
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6, ScapyPacket, ScapyTCP


DATABASE.load()


BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE_DIR.parent /  'media' / 'pcap_files'



def handle_packet(packet: ScapyPacket) -> None:
    try:
        flags = TCPFlag(int(packet[ScapyTCP].flags))

        # SYN/SYN+ACK packet, fingerprint
        if flags in (TCPFlag.SYN, TCPFlag.SYN | TCPFlag.ACK):
            mtu_result = fingerprint_mtu(packet)
            tcp_result = fingerprint_tcp(packet)
            print(f"MTU fingerprint match: {mtu_result.match}")
            print(f"TCP fingerprint match: {tcp_result.match}")

        payload = packet[ScapyTCP].payload

        if payload:
            try:
                http_result = fingerprint_http(bytes(payload))
                print(f"HTTP fingerprint match: {http_result.match}")
            except PacketError:
                print("Not an HTTP payload, skipping fingerprint")
    except Exception as e:
        # traceback.print_exc()
        print(e)






# connect to database
async def connect_db():
    conn = psycopg2.connect(
        database=config('DB_NAME'),
        host=config('DB_HOST'),
        user=config('DB_USER'),
        password=config('DB_PASSWORD'),
        port=config('DB_PORT')
    )
    return conn

# from threading import Thread

# save pcap files
async def packet_callback(sniffed_pkts):
    for pkt in sniffed_pkts:
        if IP in pkt:
            # -------------------------------------------
            # detect os
            # handle_packet(pkt)
            # -------------------------------------------
            try:
                x = pkt[IP].src 
                y = pkt[IP].dst
                if x:
                    filename = x.replace(".", "_") 
                    filename = PCAP_DIR.joinpath(filename + ".pcap")
                    with open(filename, 'ab+') as pcap_file:
                        wrpcap(pcap_file, pkt,  append=True)
                if y:
                    filename = y.replace(".", "_") 
                    filename = PCAP_DIR.joinpath(filename + ".pcap")
                    with open(filename, 'ab+') as pcap_file:
                        wrpcap(pcap_file, pkt,  append=True)
            except FileNotFoundError:
                os.makedirs(PCAP_DIR, exist_ok=True)
                # traceback.print_exc()
            except :
                traceback.print_exc()
        else:
            try:
                filename = PCAP_DIR.joinpath("dummy" + ".pcap")
                with open(filename, 'ab+') as pcap_file:
                    wrpcap(pcap_file, pkt,  append=True)
            except:
                pass


    print("Saving pcap_files")

# # save pcap files
# async def packet_callback(sniffed_pkts):
#     for pkt in sniffed_pkts:
#         if IP in pkt:
#             try:
#                 x = pkt[IP].src 
#                 y = pkt[IP].dst
#                 if x:
#                     filename = x.replace(".", "_") 
#                     filename = PCAP_DIR.joinpath(filename + ".pcap")
#                     with open(filename, 'ab+') as pcap_file:
#                         wrpcap(pcap_file, pkt,  append=True)
#                 if y:
#                     filename = y.replace(".", "_") 
#                     filename = PCAP_DIR.joinpath(filename + ".pcap")
#                     with open(filename, 'ab+') as pcap_file:
#                         wrpcap(pcap_file, pkt,  append=True)
#             except FileNotFoundError:
#                 os.makedirs(PCAP_DIR, exist_ok=True)
#                 traceback.print_exc()
#             except :
#                 traceback.print_exc()

#     print("Saving pcap_files")


# sniffing callback function
def sniff_packet_callback(packet):
    # print(packet.summary()) 
    if IP in packet:
        try:
            x = packet[IP].src 
            y = packet[IP].dst
            if x:
                filename = x.replace(".", "_") 
                filename = PCAP_DIR.joinpath(filename + ".pcap")
                with open(filename, 'ab+') as pcap_file:
                    wrpcap(pcap_file, packet,  append=True)
            if y:
                filename = y.replace(".", "_") 
                filename = PCAP_DIR.joinpath(filename + ".pcap")
                with open(filename, 'ab+') as pcap_file:
                    wrpcap(pcap_file, packet,  append=True)
        except FileNotFoundError:
            os.makedirs(PCAP_DIR, exist_ok=True)
        except :
            traceback.print_exc()
    print("Saving pcap_files")


def decode_before_saving(string):
    is_writable = False
    try:
        string.decode('utf-8', "ignore").encode("utf-8", "ignore")
    except Exception as e:
        # print(e)
        # return None
        is_writable= False

    return is_writable

# def get_packet_layers(packet):
#     counter = 0
#     while True:
#         layer = packet.getlayer(counter)
#         if layer is None:
#             break

#         yield layer
#         counter += 1



def decode_string(payload):
    try:    
        
        s1 = payload.decode('UTF8', "ignore")
        s2 = s1.encode('UTF8', "ignore")
        s3 = s2.decode('UTF8', "ignore")
        return s3
    except Exception as e:
        print("Error in decode_string")
        return None



def read_payload(packet):
    payload = None
    try:
        if TCP in packet:
            payload = decode_string(packet[TCP].payload)
        if Raw in packet:
            payload = decode_string(packet[Raw].load)
    except :
        pass
    # print(payload)
    return payload


# save packets to db
async def save_packets(sniffed_pkts, cursor, conn):

    pkts = monitor_service.get_packer_details(sniffed_pkts)
    postgres_insert_query = """ INSERT INTO master_app_packets(
        destination_ip, 
        source_ip, 
        protocol,
        src_port, 
        dst_port, 
        payload,
        date,
        time
        ) VALUES (%s,%s, %s, %s, %s, %s , %s, %s);"""
        
    for pkt in pkts:
        # print(pkt)
        # pkt_id = str(uuid.uuid4())
        # print(base64.b64encode(read_payload((pkt[8]))))
        # print(pkt[8])
        # print(pkt[8].build())
        # print(base64.b64encode(pkt[8].build()),)
        # for layer in get_packet_layers(pkt[8]):
        #     print (layer.name)

        # print(packet.payload.layers())

        # print(str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        # print(pkt[8].bui

        # print( str(base64.b64encode(read_payload((pkt[8])))))
        # print(read_payload((pkt[8])))
        # print(datetime.now().strftime("%H:%M:%S"))
        try:
            if pkt[5]:
                record_to_insert = ( 
                    pkt[0], # src port
                    pkt[1], # dst port
                    pkt[2], # protocol 
                    pkt[3], # src port
                    pkt[4], # dst port
                    # pkt[5],  
                    # str(bytes(pkt[6],"utf-8")),
                    # str(base64.b64encode(read_payload((pkt[8])))),
                    pkt[5],
                    date.today(),
                    datetime.now().strftime("%H:%M:%S")
                    # "",
                    # False
                    # base64.b64encode(bytes(pkt[6],"utf-8")),
                    # str(pkt[7]), 
                    # str(base64.b64encode(read_payload((pkt[8])))),
                    # str(base64.b64encode(pkt[8].build())),
                    # str(base64.b64encode(pkt[8].build())),
                    # str("N"),
                    # str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                # print(record_to_insert)
                cursor.execute(postgres_insert_query, record_to_insert)
                conn.commit()
                print("Saving database")
        except psycopg2.errors.InFailedSqlTransaction as e:
            print(e)
            conn.rollback()

        except Exception as e:
            traceback.print_exc()


async def collect_packets(cursor, conn):
    timeout_seconds = 0.1
    while True:
        print("Capturing")
        start_time = time.time()
        sniffed_pkts = []
        while time.time() - start_time < timeout_seconds:
            sniffed_pkts = [pkt for pkt in sniff( iface=config('NETWORK_INTERFACE_LABEL') ,timeout=0.1 )]
        await save_packets(sniffed_pkts, cursor=cursor, conn=conn)
        await packet_callback(sniffed_pkts)


async def main():
    conn = await connect_db()
    cursor = conn.cursor()
    print("Starting")
    
    await collect_packets(cursor=cursor, conn=conn)
    

asyncio.run(main())

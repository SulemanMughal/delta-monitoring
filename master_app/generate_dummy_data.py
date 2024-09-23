# import os
# import sys
# import django

from scapy.all import *
import random
from scapy.all import *
from ipaddress import IPv4Address, IPv4Network

import json
import time
from scapy.all import *
from decouple import config
import requests
import psycopg2
import uuid
from datetime import datetime, timezone
import traceback

import asyncio


# from master_app.models import Packet



async def connect_db():
    conn = psycopg2.connect(
        database=config('DB_NAME'),
        host=config('DB_HOST'),
        user=config('DB_USER'),
        password=config('DB_PASSWORD'),
        port=config('DB_PORT')
    )
    return conn



# save packets to db
async def save_packets(packet, cursor, conn):
    
    # print(packets)
    # print("Saving Packets")
    postgres_insert_query = """ INSERT INTO master_app_packets(id, destination_ip, source_ip, type, protocol,src_port, dst_port, payload, is_namp, summary, timestamp) VALUES(%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    # for packet in packets:
    try:
        dt = datetime.now(timezone.utc)
        dt = dt.strftime("%Y-%m-%d %H:%M:%S")
        record_to_insert = ( str(uuid.uuid4()), packet["dst_ip"] , packet["src_ip"], "Ipv4", packet["src_port"], "Ipv4", packet["dst_port"], packet["payload"],packet["is_namp"], packet["summary"], str(dt))
        cursor.execute(postgres_insert_query, record_to_insert)
        conn.commit()
        print("Saved")
    except Exception as e:
        cursor.execute("ROLLBACK")
        traceback.print_exc()
    return None

def generate_subnet_ips(base_ip, subnet_mask):
    base_ip_obj = IPv4Address(base_ip)
    subnet_network = IPv4Network(f"{base_ip}/{subnet_mask}", strict=False)
    prefix_length = subnet_network.prefixlen
    num_hosts = 2**(32 - prefix_length) - 2
    subnet_ips = [str(ip) for ip in subnet_network.hosts()]
    return subnet_ips



async def main():
    # print("Start Capturing")
    conn = await connect_db()
    cursor = conn.cursor()
    # subnetting
    # base_ip = "192.168.0.0"
    subnet_mask = "255.255.0.0"

    subnet_ips_src = generate_subnet_ips("192.168.0.0", subnet_mask)
    subnet_ips_dst = generate_subnet_ips("172.165.0.0", subnet_mask)


    nmap_choice = ["Y", "N"]

    for i in range(0, 200000):
        src_ip = random.choice(subnet_ips_src)
        dst_ip = random.choice(subnet_ips_dst)
        await save_packets({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(0, 65535),
            "dst_port": random.randint(0, 65535),
            "payload": "This is a payload",
            "protocol": "TCP",
            "type": "",
            "summary": "This is a summary",
            "is_namp": random.choice(nmap_choice)
        }, cursor=cursor, conn=conn)
    

    cursor.close()
    conn.close()


asyncio.run(main())
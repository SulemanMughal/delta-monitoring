import requests
import os
from dotenv import load_dotenv

import json
import time
from scapy.all import *
# from decouple import config
import requests
import psycopg2
import uuid
from datetime import datetime, timezone, timedelta
import traceback
# import os
# import monitor_service
import asyncio
from pathlib import Path
import base64

from pytz import timezone
from datetime import datetime
from psycopg2 import sql, extras
from pprint import pprint 



load_dotenv()

requests.packages.urllib3.disable_warnings()

TARGET_URL = os.getenv('LOGS_URL')
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
WAF_LOGS_URL = os.getenv('WAF_LOGS_URL')
ANOMALY_LOGS_URL = os.getenv('ANOMALY_LOGS_URL')



# print(TARGET_URL, ACCESS_TOKEN)


# connect to the db


# connect to database
async def connect_db():
    conn = psycopg2.connect(
        database=os.getenv('DB_NAME'),
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        port=os.getenv('DB_PORT')
    )
    
    return conn



# def convertToMilliseconds(timestamp):
#     return int(timestamp * 1000)


# convert datetime to milliseconds
def convertToMilliseconds(timestamp):
    return int(timestamp.timestamp() * 1000)



def convertMilliToTime(timestamp):
    return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]





# def convertMilliToTime(timestamp):
#     return datetime.fromtimestamp(timestamp / 1e9, tz=timezone('Asia/Urumqi')).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]



# def get_logs_details(logs):
    # return logs['results']


def generate_id(num):
    return int(str(int((uuid.uuid5(uuid.NAMESPACE_DNS, str(num)))))[:18])

def read_list_through_yield(lst):
        for item in lst:
            yield item

async def save_logs(logs, cursor, conn):
    try:
        postgres_insert_query = sql.SQL(""" INSERT INTO master_app_external(
            log_id, 
            destination_ip, 
            source_ip, 
            protocol,
            src_port, 
            dst_port, 
            attack_name,
            payload,
            severity,
            date,
            time) VALUES %s  ON CONFLICT (log_id) DO NOTHING;""")
        data = [
            (
                generate_id(item["_metadata"]["#"]+item["_metadata"]["logid"]+item["_metadata"]["timestamp"]),
                item["dstip"],
                item["srcip"],
                str([item["service"]]),
                item["srcport"],
                item["dstport"],
                item.get("attack" , ""),
                str(f"{item.get('msg', '')}\n{item.get('agent', '')}\n{item.get('direction', '')}\n{item.get('url', '')}"),
                item.get("severity", "High"),
                item["date"],
                item["time"]
            )
            for item in read_list_through_yield(logs["results"])
        ]

        # pprint(data)

        extras.execute_values(cursor, postgres_insert_query, data)
        conn.commit()
        print("saving database")
    except psycopg2.errors.InFailedSqlTransaction as e:
        print(e)
        conn.rollback()
    except :
        conn.rollback()
        traceback.print_exc()


    # for item in read_list_through_yield(logs["results"]):
    #     # print(item)
    #     record_to_insert = (
    #         item["logid"],
    #         item["dstip"],
    #         item["srcip"],
    #         "Ipv4",
    #         "TCP",
    #         item["srcport"],
    #         item["dstport"],
    #         item["msg"],
    #         convertMilliToTime(item["_metadata"]["timestamp"])
    #     )
    #     try:
    #         cursor.execute(postgres_insert_query, record_to_insert)
    #         conn.commit()
    #     except :
    #         traceback.print_exc()

async def fetch_and_update_data(start_time, end_time,cursor, conn):
    try:
        params = {
            'start': '0',
            'extra': [
                'country_id',
                'reverse_lookup',
            ],
            # 'filter': f"_metadata.timestamp>='{1706006137000}'",
            # 'filter': f"_metadata.timestamp<='{1706013337000}'",
            "filter" : {
                "_metadata.timestamp" : f"{start_time} -> {end_time}"
                # {
                #     "start" : start_time,
                #     "end" : end_time
                # }
            },
            'serial_no': 'FG200FT923900876',
            'vdom': 'root',
            'access_token' : ACCESS_TOKEN,
        }
        response = requests.get(
            TARGET_URL,
            params=params,
            verify=False,
            timeout=5
        )

        if(response.status_code == 200):
            # pprint(response.json())
            await save_logs(response.json(), cursor, conn)
            # return response.json()
        else:
            print(response.status_code)
            print(response.content)
            return None
    except requests.exceptions.ConnectTimeout as e:
        print(e)
    except :
        traceback.print_exc()



async def fetch_and_update_waf_logs(start_time, end_time,cursor, conn):
    try:
        params = {
            'start': '0',
            'extra': [
                'country_id',
                'reverse_lookup',
            ],
            # 'filter': f"_metadata.timestamp>='{1706006137000}'",
            # 'filter': f"_metadata.timestamp<='{1706013337000}'",
            "filter" : {
                "_metadata.timestamp" : f"{start_time} -> {end_time}"
                # {
                #     "start" : start_time,
                #     "end" : end_time
                # }
            },
            'serial_no': 'FG200FT923900876',
            'vdom': 'root',
            'access_token' : ACCESS_TOKEN,
        }
        response = requests.get(
            WAF_LOGS_URL,
            params=params,
            verify=False,
            timeout=5
        )

        if(response.status_code == 200):
            # pprint(response.json())
            await save_logs(response.json(), cursor, conn)
            # return response.json()
        else:
            print(response.status_code)
            print(response.content)
            return None
    except requests.exceptions.ConnectTimeout as e:
        print(e)
    except :
        traceback.print_exc()



async def fetch_and_update_anomaly_logs(start_time, end_time,cursor, conn):
    try:
        params = {
            'start': '0',
            'extra': [
                'country_id',
                'reverse_lookup',
            ],
            # 'filter': f"_metadata.timestamp>='{1706006137000}'",
            # 'filter': f"_metadata.timestamp<='{1706013337000}'",
            "filter" : {
                "_metadata.timestamp" : f"{start_time} -> {end_time}"
                # {
                #     "start" : start_time,
                #     "end" : end_time
                # }
            },
            'serial_no': 'FG200FT923900876',
            'vdom': 'root',
            'access_token' : ACCESS_TOKEN,
        }
        response = requests.get(
            ANOMALY_LOGS_URL,
            params=params,
            verify=False,
            timeout=5
        )

        if(response.status_code == 200):
            # pprint(response.json())
            await save_logs(response.json(), cursor, conn)
            # return response.json()
        else:
            print(response.status_code)
            print(response.content)
            return None
    except requests.exceptions.ConnectTimeout as e:
        print(e)
    except :
        traceback.print_exc()




update_interval = timedelta(seconds=5)

async def collect_logs(cursor, conn):
    while True:
        pprint("Collecting logs")
        # start current time from previous 10 hours
        

        current_time = datetime.now()
        # start_time = (current_time - timedelta(hours=5, seconds=13))
        start_time = (current_time - timedelta(seconds=8))
        end_time = current_time
        # end_time = (current_time - timedelta(hours=5))
        # print(convertToMilliseconds(start_time), convertToMilliseconds(end_time))
        await fetch_and_update_data(convertToMilliseconds(start_time), convertToMilliseconds(end_time), cursor, conn)
        await fetch_and_update_waf_logs(convertToMilliseconds(start_time), convertToMilliseconds(end_time), cursor, conn)
        await fetch_and_update_anomaly_logs(convertToMilliseconds(start_time), convertToMilliseconds(end_time), cursor, conn)
        
        next_update_time = current_time + update_interval
        sleep_duration = (next_update_time - current_time).total_seconds()
        time.sleep(max(0, sleep_duration))


# timestamp_in_seconds = 1706139180000
# dt_object = datetime.utcfromtimestamp(timestamp_in_seconds)
# formatted_datetime = dt_object.strftime("%Y-%m-%d %H:%M:%S")
# print(formatted_datetime)

# print(convertMilliToTime(timestamp_in_seconds))




# 
async def main():
    conn = await connect_db()
    cursor = conn.cursor()
    print("Starting")

    await collect_logs(cursor=cursor, conn=conn)

    

    




asyncio.run(main())
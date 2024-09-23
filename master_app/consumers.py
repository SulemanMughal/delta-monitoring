# import asyncio
import json
from channels.consumer import AsyncConsumer
from channels.db import database_sync_to_async

from . import monitoring

from .models import *

class PracticeConsumer(AsyncConsumer):

    async def websocket_connect(self,event):
        # when websocket connects
        print("connected",event)
        

        await self.send({"type": "websocket.accept",
                         })

        await self.send({"type":"websocket.send",
                         "text":0})
        

    # when messages is received from websocket
    async def websocket_receive(self,event):
        print("connected",event)
        sniffed_pkts = monitoring.collect_packets()
        # print("sniffed_pkts", sniffed_pkts)
        pkts = monitoring.get_packet_list(sniffed_pkts)
        # print("pkts", pkts)
        json_data = json.dumps(pkts)
        # print(json_data)
        

        await self.send({
            "type": "websocket.send"
            ,"text": json_data
        })
        

        # await self.send({"type": "websocket.send"
        #                  , 
        #                  "text": json.dumps([count])})
        


    @database_sync_to_async
    def save_to_database(self, result):
        monitoring.save_packets(result)

    @database_sync_to_async
    def get_total_packets_count(self):
        return Packets.objects.all().count()
  

    async def websocket_disconnect(self, event):
        # when websocket disconnects
        print("disconnected", event)
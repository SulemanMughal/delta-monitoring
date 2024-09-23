from scapy.all import *
from os.path import isfile
from datetime import datetime
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning) 

__list = []

def format(request, response) -> str:

    def get_ent(it, field, alternate=''):
        it = it.get(field, alternate)
        if type(it) != str and it: it = it.decode()
        return it

    FMT = '{SRC_IP} - - [{DATE}] "{METHOD} {ENDPOINT} {HTTP_VER}" {STATUS_CODE} {LEN} {REFERER} {USER_AGENT}'

    rcv_time = request.time
    rcv_time = datetime.fromtimestamp(rcv_time).strftime('%Y-%m-%d %H:%M:%S')
    src_ip = request['IP'].src
    req_fields = request['HTTPRequest'].fields
    resp_fields = response['HTTPResponse'].fields

    referer = get_ent(req_fields, 'Referer', alternate='""')
    status_code = get_ent(resp_fields, 'Status_Code')
    user_agent = get_ent(req_fields, 'User_Agent')
    method = request['HTTPRequest'].Method.decode()
    path = request['HTTPRequest'].Path.decode()
    http_ver = request['HTTPRequest'].Http_Version.decode()
    _len = len(response['HTTPResponse'].payload)

    return FMT.format(
        SRC_IP=src_ip,
        DATE=rcv_time,
        METHOD=method,
        ENDPOINT=path,
        HTTP_VER=http_ver,
        STATUS_CODE=status_code,
        LEN=_len,
        REFERER=referer,
        USER_AGENT=user_agent
    )

def __parse__(pkt):
    global __list
    if pkt.haslayer(HTTPRequest):
        __list.append(pkt)
    elif pkt.haslayer(HTTPResponse):
        for i in range(len(__list)):
            p = __list[i]
            if pkt.answers(p) == 1:
                fmt = format(request=p, response=pkt)
                print(fmt)
                with open("access.log", "a") as f:
                    f.write(f"{fmt}\n")
                del __list[i]
                break

if __name__ == "__main__":
    load_layer('http')
    pkts = rdpcap("10_12_120_189.pcap")
    for pkt in pkts:
        __parse__(pkt)
    pass
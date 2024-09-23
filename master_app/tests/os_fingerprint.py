from scapy.layers.inet import IP, TCP
from scapy.all import *

from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult


DATABASE.load()  # Load the fingerprints database

import base64

b = raw(base64.b64decode("hDmPjTx6AkKspQucCABFAAA0AABAAEAGy3CspQucrBALAgWZxSjDng9MsfUAiIAS+vC0kgAAAgQFtAEBBAIBAwMH"))

c = Ether(b)
print(c)
mtu_result: MTUResult = fingerprint_mtu(c)
print(mtu_result)

tcp_result: TCPResult = fingerprint_tcp(c)
print(tcp_result)

apache_payload = b"HTTP/1.1 200 OK\r\nDate: Fri, 10 Jun 2011 13:27:01 GMT\r\nServer: Apache\r\nLast-Modified: Thu, 09 Jun 2011 17:25:43 GMT\r\nExpires: Mon, 13 Jun 2011 17:25:43 GMT\r\nETag: 963D6BC0ED128283945AF1FB57899C9F3ABF50B3\r\nCache-Control: max-age=272921,public,no-transform,must-revalidate\r\nContent-Length: 491\r\nConnection: close\r\nContent-Type: application/ocsp-response\r\n\r\n"
http_result: HTTPResult = fingerprint_http(apache_payload)

print(http_result)

# print(b)


#!/usr/bin/env python

from scapy.all import *
from scapy.layers.http import *
from scapy.layers import http
import random
import sys


load_layer("http")
req = HTTP()/HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'localhost',
    Pragma=b'no-cache'
)
a = TCP_client.tcplink(HTTP, "127.0.0.1", 5000)
answser = a.sr1(req)
a.close()
with open("127.0.0.1", "wb") as file:
    file.write(answser.load)

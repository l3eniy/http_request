#!/usr/bin/env python

from scapy.all import PcapReader, wrpcap, Packet, NoPayload
from scapy.all import *



vtep="192.168.10.149"
source_ip="172.20.10.254"
vxlanport=4789     # RFC 7384 port 4789, Linux kernel default 8472
vni = 1
broadcastmac="ff:ff:ff:ff:ff:ff"
randommac="00:51:52:01:02:03"

# send vxlan packet
send(IP(src=source_ip,dst=vtep)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vni,flags="Instance")/Ether(dst=broadcastmac,src=randommac))

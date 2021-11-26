from scapy.all import *
import threading
#import p4runtime_sh.shell as sh
#from p4runtime_sh.shell import PacketIn

class MyTag(Packet):
    name = "IMSI"
    fields_desc = []

    pkt_ip = IP()

    if pkt_ip.src == '10.0.2.15': #interface enp0s3
        fields_desc.append(StrLenField("imsi","310170845466094",1111))
    else:
        fields_desc.append(StrLenField("imsi","5021301234567894",1111))

def receive():
    while True:
        packets = None
        packets = sniff(timeout=5)
        packetHandler(packets)

def packetHandler(packets):
    for pkt in packets:
        print("[!] Packets received")
        pkt_payload = packet.payload
        
        if pkt.getlayer(IP) != None:
            pkt_src = pkt.getlayer(IP).src
            pkt_dst = pkt.getlayer(IP).dst
        
        pkt_ip = pkt.getlayer(IP)
        pkt_imsi = pkt.getlayer(MyTag)

        print(packet.getlayer('IP').src)
        print(packet.getlayer('IP').dst)
        print(packet.getlayer('MyTag').imsi)
        print(packet.getlayer('TCP').dport)


#print(IP().show())
#print(TCP().show())
#print(UDP().show())
#print(MyTag().show())

#test_pkt_tag = MyTag(imsi = 310170845466094)
#test_pkt_ip = IP(ttl=100)
#test_pkt_ip.dst = '8.8.8.8'
#print(test_pkt_ip.src)
#print(test_pkt_ip.dst)
#print(test_pkt_tag.imsi) #ok -> imsi set inside mytag layer


#print("\n\n\n\n\n\nnow test /w a packet")

packet = MyTag(imsi = 5021301234567894)/IP(ttl = 100, dst = '10.0.2.15')/TCP(dport=53, flags='S')

receiver = threading.Thread(target = receive)
receiver.start()

send(packet)
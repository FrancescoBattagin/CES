from scapy.all import *

class MyUDP(UDP):
    fields_desc = UDP.fields_desc.copy()
    #fields_desc.append(StrLenField("imsi","310170845466094",1111))

    pkt_ip = IP()

    if pkt_ip.src == '10.0.2.15': #interface enp0s3
        fields_desc.append(StrLenField("imsi","310170845466094",1111))
    else:
        fields_desc.append(StrLenField("imsi","5021301234567894",1111))

class MyTCP(TCP):
    fields_desc = TCP.fields_desc.copy()
    #fields_desc.append(StrLenField("imsi","5021301234567894",1111))

    pkt_ip = IP()

    if pkt_ip.src == '10.0.2.15': #interface enp0s3
        fields_desc.append(StrLenField("imsi","5021301234567894",1111))
    else:
        fields_desc.append(StrLenField("imsi","310170845466094",1111))


print(IP().show())
print(MyTCP().show())
print(MyUDP().show())

test_pkt_ip = IP(ttl=100)
test_pkt_ip.dst = '8.8.8.8'
test_pkt_tcp = TCP()
test_pkt_tcp.imsi = "310170845466094"
test_pkt_udp = UDP()
test_pkt_udp.imsi = "5021301234567894"
print(test_pkt_ip.src)
print(test_pkt_ip.dst)
print(test_pkt_tcp.imsi) #ok -> imsi 310170845466094 is the def one for udp, so field setting works
print(test_pkt_udp.imsi) #ok -> imsi 5021301234567894 is the def one for tcp, so field setting works
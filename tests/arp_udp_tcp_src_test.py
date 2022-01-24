from scapy.all import *
import time
import requests

SELF_MAC = 'b6:71:cd:b3:d5:f2'
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = "10.0.0.1", hwsrc = SELF_MAC, pdst = "172.17.0.1")
sendp(packet, iface="src-eth0")

time.sleep(2)

def auth_param(param):
	return param + "-"

class Auth(Packet):
    '''Add a '-' at the and of each field value but the last for parsing inside orchestrator'''
    fields_desc = []
    fields_desc.append(StrLenField("service_ip", auth_param("10.0.0.1"))) #10.0.0.1 as default
    fields_desc.append(StrLenField("method", auth_param("imsi"))) #imsi as default
    fields_desc.append(StrLenField("authentication", auth_param("310170845466094"))) #310170845466094 as default
    fields_desc.append(StrLenField("port", auth_param("33440"))) #80 as default
    fields_desc.append(StrLenField("protocol", "TCP")) #TCP as default

packet = Ether(dst = BCAST_MAC, src = SELF_MAC)/IP(src="10.0.0.1", dst="10.0.0.3")/UDP(sport=1298, dport=1299)/Auth(service_ip = auth_param("10.0.0.3"), method = auth_param("ip"), authentication = auth_param("10.0.0.1"), port = auth_param("80"), protocol = "TCP")

sendp(packet, iface="src-eth0")

time.sleep(2)

#URL = "http://10.0.0.3:80/get_file?name=tcp_test.py"
#r = requests.get(url=URL)
#print(r)
packet = Ether(dst = "02:42:ba:6c:52:f5", src = SELF_MAC)/IP(src="10.0.0.1", dst="10.0.0.3")/TCP(sport=1298, dport=80, flags='S', seq=1000)
sendp(packet, iface="src-eth0")

time.sleep(10)

packet = Ether(dst = "02:42:ba:6c:52:f5", src = SELF_MAC)/IP(src="10.0.0.1", dst="10.0.0.3")/TCP(sport=1298, dport=80, flags='A', seq=1001)
sendp(packet, iface="src-eth0")
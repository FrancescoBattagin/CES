from scapy.all import *
import time

SELF_MAC = '8e:25:fb:b3:13:d7'
BCAST_MAC = 'b6:71:cd:b3:d5:f2'

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = "10.0.0.3", hwsrc = SELF_MAC, pdst = "172.17.0.1")
sendp(packet, iface="dst-eth0")

def auth_param(param):
        return param + "-"

class Auth(Packet):
    '''Add a '-' at the and of each field value but the last for parsing inside orchestrator'''
    fields_desc = []
    fields_desc.append(StrLenField("service_ip", auth_param("10.0.0.1"))) #10.0.0.1 as default
    fields_desc.append(StrLenField("method", auth_param("imsi"))) #imsi as default
    fields_desc.append(StrLenField("authentication", auth_param("310170845466094"))) #310170845466094 as default
    fields_desc.append(StrLenField("port", auth_param("80"))) #80 as default
    fields_desc.append(StrLenField("protocol", "TCP")) #TCP as default

time.sleep(5)

packet = Ether(dst = BCAST_MAC, src = SELF_MAC)/IP(src="10.0.0.3", dst="10.0.0.1")/TCP(sport=80, dport=1298, flags='S', seq=10001)

sendp(packet, iface="dst-eth0")

from scapy.all import *
import time

SELF_MAC = '08:00:27:fe:41:93'
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
controller_ether = '08:00:27:ef:14:c0'

packet = Ether(dst = controller_ether, src = SELF_MAC, type = 0x0806)/ARP(psrc = "192.169.56.2", hwsrc = SELF_MAC, pdst = "192.168.56.2")
sendp(packet, iface="eth1")

time.sleep(5)

packet = Ether(dst = controller_ether, src = SELF_MAC)/IP(src="192.169.56.2", dst="192.168.56.1")/TCP(sport=80, dport=1298, flags='S', seq=10001)

sendp(packet, iface="eth1")
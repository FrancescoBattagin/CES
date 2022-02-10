from scapy.all import *
import time
import requests
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64

controller_ip = '192.168.56.4'
controller_ether = '08:00:27:36:e0:ab'
BCAST_MAC = "ff:ff:ff:ff:ff:ff"
SELF_MAC = "08:00:27:13:cd:9d"
self_ip = "192.168.56.1"

packet = Ether(dst = BCAST_MAC, src = SELF_MAC, type = 0x0806)/ARP(psrc = self_ip, hwsrc = SELF_MAC, pdst = controller_ip)
sendp(packet, iface="eth1")

time.sleep(2)

class Auth():

    def __init__(self, service_ip, method, authentication, port, protocol, imsi, count):
        self.service_ip = service_ip
        self.method = method
        self.authentication = authentication
        self.port = str(port)
        self.protocol = protocol
        self.imsi = imsi
        self.count = count

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__

auth = Auth("10.0.0.3", "ip", "10.0.0.1", 80, "TCP", "302130123456789", 1)
auth = MyEncoder().encode(auth)
key = dh("302130123456789")
message_bytes = auth.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
msg = str(base64_bytes) + '---' + str(hmac_hex)

packet = Ether(dst = BCAST_MAC, src = SELF_MAC)/IP(dst="192.168.56.4", src=self_ip)/UDP(sport=1298, dport=101)/msg

sendp(packet, iface="eth1")

time.sleep(3)

sendp(packet, iface="eth1") #count is the same -> request is expected not to be handled by controller
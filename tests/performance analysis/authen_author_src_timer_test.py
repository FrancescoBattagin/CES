from scapy.all import *
import time
from diffie_hellman_ue import dh
import json
from json import JSONEncoder
import hmac, hashlib, base64
import socket

def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("45.45.0.2", 1298))
    print("CONNECTION AT: " + str(time.time()))
    s.connect((hostname, port))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    print("Connection closed.")
    s.close()

controller_ip = '192.168.56.2'
self_ip = "45.45.0.2"
iface = 'oaitun_ue1'
auth_port = 101
time_limit = 30

class Auth():

    def __init__(self, service_ip, method, authentication, port, protocol, imsi, count, version):
        self.service_ip = service_ip
        self.method = method
        self.authentication = authentication
        self.port = str(port)
        self.protocol = protocol
        self.imsi = imsi
        self.count = count
        self.version = version

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__

auth = Auth("192.169.56.2", "ip", "192.168.56.1", 80, "TCP", "302130123456789", 1, 1.0)
auth = MyEncoder().encode(auth)
key = dh("302130123456789")
message_bytes = auth.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
hmac_hex = hmac.new(bytes(key, 'utf-8'), base64_bytes, hashlib.sha512).hexdigest()
msg = str(base64_bytes) + '---' + str(hmac_hex)
packet = IP(dst=controller_ip, src=self_ip)/UDP(sport=1298, dport=auth_port)/msg


def test():
    for i in range(1,100):
        dh("302130123456789")
        sendp(packet, iface=iface)
        print("AUTH PKT SENT AT " + str(time.time()))
        netcat("192.169.56.2", 80, b"ciao")
    return

flag = time.time()
while True:
    if flag-time.time() < time_limit:
        thread = threading.Thread(target = test).start()
import random
import hashlib
import sys
from scapy.all import *
import json
from json import JSONEncoder

controller_ip = '192.168.56.4'
controller_ether = '08:00:27:36:e0:ab'
BCAST_MAC = "ff:ff:ff:ff:ff:ff"
SELF_MAC = "08:00:27:13:cd:9d"
self_ip = "192.168.56.1"
key = ''

def isPrime(k):
    if k==2 or k==3: return True
    if k%2==0 or k<2: return False
    for i in range(3, int(k**0.5)+1, 2):
        if k%i==0:
            return False

    return True

class DH():

    def __init__(self, p, g, A, imsi):
        self.p = p
        self.g = g
        self.A = A
        self.imsi = imsi

class MyEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__


#generates prime numbers
def dh(identity):
    minPrime = 0
    maxPrime = 1001
    cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]
    p = random.choice(cached_primes)
    g = random.randint(2, 100)
    a = random.randint(2, 100)
    A = (g**a) % p
    imsi = identity

    #[...] sends p, g, A to controller, waits for B
    dh = DH(p, g, A, imsi)
    dh = MyEncoder().encode(dh)
    pkt = Ether(dst = BCAST_MAC, src = "08:00:27:36:e0:ab")/IP(src = self_ip, dst = controller_ip)/UDP(sport = 1298, dport = 100)/str(dh)
    print(p)
    print(g)
    print(A)
    print(imsi)
    sendp(pkt, iface = 'eth1')

    def key_computation(pkt):
        global key
        print("Raw: ")
        raw = str(pkt.getlayer(Raw)).split("-")
        B = raw[1]
        print(B)
        keyA = hashlib.sha256(str((int(B)**int(a)) % int(p)).encode()).hexdigest()
        #print(keyA)
        key = keyA

    #waits for B
    packet = sniff(prn = lambda x:key_computation(x), count = 1, iface='eth1', filter = 'src host 192.168.56.4 and src port 100')
    return key

#--- controller ---
#[...] receives p, g, A
#b=random.randint(10,20)
#B = (g**b) % p
#sends B to ue
#keyB = hashlib.sha256(str((A**b) % p).encode()).hexdigest()
#print(keyB)
#saves key for specific ue
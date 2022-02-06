import random
import hashlib
import sys
from scapy.all import *

controller_ip = '192.168.56.4'
controller_ether = '08:00:27:36:e0:ab'

def isPrime(k):
    if k==2 or k==3: return True
    if k%2==0 or k<2: return False
    for i in range(3, int(k**0.5)+1, 2):
        if k%i==0:
            return False

    return True

class DH(Packet):
    '''Add a '-' at the and of each field value but the last for parsing inside orchestrator'''
    fields_desc = []
    fields_desc.append(StrLenField("p", "2-"))
    fields_desc.append(StrLenField("g", "5-"))
    fields_desc.append(StrLenField("A", "10-"))
    fields_desc.append(StrLenField("imsi", "5021301234567894-"))

#generates prime numbers
minPrime = 0
maxPrime = 1001
cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]
p = random.choice(cached_primes)
g = random.randint(2, 100)
a = random.randint(2, 100)
A = (g**a) % p
imsi = "5021301234567894"
print(p)
print(g)
print(A)

#[...] sends p, g, A to controller, waits for B
pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", src = "08:00:27:36:e0:ab")/IP(src="45.45.0.2", dst=controller_ip)/UDP(sport=1298, dport=100)/DH(p = str(p) + "-", g = str(g) + "-", A = str(A) + "-", imsi = "3021301234567894" + "-") #check
pkt_dh = str(pkt.getlayer(DH)).split("-")
print(pkt_dh)
p = pkt_dh[0][2:] #remove 'b
print(p)
g = pkt_dh[1]
print(g)
A = pkt_dh[2]
print(A)
imsi = pkt_dh[3]
print(imsi)
#answer = sr1(pkt, iface='eth1')
sendp(pkt, iface = 'eth1')

def key_computation(pkt):
    print("Raw: ")
    raw = str(pkt.getlayer(Raw)).split("-")
    B = raw[1]
    print(B)
    keyA = hashlib.sha256(str((int(B)**int(a)) % int(p)).encode()).hexdigest()
    print(keyA)

#waits for B
packet = sniff(prn = lambda x:key_computation(x), count = 1, iface='eth1', filter = 'src host 192.168.56.4 and src port 100')

#--- controller ---
#[...] receives p, g, A
#b=random.randint(10,20)
#B = (g**b) % p
#sends B to ue
#keyB = hashlib.sha256(str((A**b) % p).encode()).hexdigest()
#print(keyB)
#saves key for specific ue
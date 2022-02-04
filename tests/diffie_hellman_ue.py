import random
import hashlib
import sys
from scapy.all import *

controller_ip = '192.168.56.4'

def isPrime(k):
    if k==2 or k==3: return True
    if k%2==0 or k<2: return False
    for i in range(3, int(k**0.5)+1, 2):
        if k%i==0:
            return False

    return True

#generates prime numbers
minPrime = 0
maxPrime = 1001
cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]
p = random.choice(cached_primes)
g = random.randint(2, 100)
a = random.randint(2, 100)
A = (g**a) % p

data = [p, g, A]

#[...] sends p, g, A to controller, waits for B
pkt = IP(dst = controller_ip)/Raw(load = data) #checl
answer = sr1(pkt)

#[...] receives B
B = answer.getlayer(Raw)
keyA = hashlib.sha256(str((B**a) % p).encode()).hexdigest()
print(keyA)


#--- controller ---
#[...] receives p, g, A
b=random.randint(10,20)
B = (g**b) % p
#sends B to ue
keyB = hashlib.sha256(str((A**b) % p).encode()).hexdigest()
print(keyB)
#saves key for specific ue
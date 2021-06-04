#!/usr/bin/env python2
import grpc
import os, sys
from time import sleep
import socket

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/p4runtime_lib'))
import bmv2
from error_utils import printGrpcError
from switch import ShutdownAllSwitchConnections
import helper

def checkPolicies(packet):
    #TODO db query, now managed as file.txt read
    policies = []
    with open("policiesDB.txt", 'r') as f:
        line = f.readline()
        while line:
            policies.append(line.split(" "))
            line = f.readline()

    found = False
    src_dst = ipv4_head(packet)
    ip_src= src_dst[0]
    ip_dst= src_dst[1]

    for policy in policies:
        #TODO managed different types of policies -> see when they'll be defined
        if ip_src in policy and ip_dst in policy: #&& desired info are present
            found = True
            addEntries(ip_src, ip_dst)          
            break
    if not found:
        #packet drop
        packet = None
        print("packet dropped")


def addEntries(ip_src, ip_dst):
    te = p4info_helper.buildTableEntry(
        table_name="my_ingress.ipv4_lpm",
        match_fields={
            "hdr.ipv4_t.srcAddr": ip_src,
            "hdr.ipv4_t.dstAddr": ip_dst
        },
        action_name="my_ingress.ipv4_forward",
        action_params={}
    )
    ces.WriteTableEntry(te)
    print("Installed leader table entry rule on {}".format(ces.name))


def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data 


def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src_dst = [src, target]
    return src_dst



p4info_file_path = "p4-test.p4info.txt"
p4info_helper = helper.P4InfoHelper(p4info_file_path)
ces = bmv2.Bmv2SwitchConnection(
    name='ces',
    address='192.187.3.7:50051',
    device_id= 0,
    proto_dump_file='logs/ces-p4runtime.txt')

ces.MasterArbitrationUpdate()

while True:
    packet = None
    print("Waiting for receive something")
    packet = sniff(count = 1)
    
    if packet != None:
        print("Packet received!: " + {packet[0][1].src} + "==>" + {packet[0][1].dst})
        checkPolicies(packet)

#!/usr/bin/env python2
import grpc
import os, sys
from time import sleep
import p4runtime_sh.shell as sh
from scapy.all import *

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
    #read from db/txt file
    policies = []
    with open("policiesDB.txt", 'r') as f:
        line = f.readline()
        while line:
            policies.append(line.split(" "))
            line = f.readline()

    found = False
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst

    for policy in policies:
        #TODO: check device_ip, port and destination of packet inside policies
        if ip_src in policy and ip_dst in policy: #&& desired info are present
            found = True
            #TODO: add entries in table  
            addEntries(ip_src, ip_dst)          
            break
    if not found:
        #drop
        packet = None
        print("packet dropped")


def addEntries(ip_src, ip_dst):
    table_entry = p4info_helper.buildTableEntry(
        table_name="my_ingress.ipv4_lpm",
        match_fields={
            #FIX
            "hdr.ipv4_t.srcAddr": ip_src,
            "hdr.ipv4_t.dstAddr": ip_dst #ADD PORT?,
        },
        action_name="my_ingress.ipv4_forward",
        action_params={}
        )
    ces.WriteTableEntry(table_entry)
    print("Installed leader table entry rule on {}".format(ces.name))



p4info_file_path = "p4-test.p4info.txt"
p4info_helper = helper.P4InfoHelper(p4info_file_path)
ces = bmv2.Bmv2SwitchConnection(
    name='ces',
    address='192.187.3.7:50051',
    device_id= 0,
    proto_dump_file='logs/ces-p4runtime.txt')

ces.MasterArbitrationUpdate()

connection = sh.client
#print(connection)
while True:
    packet = None
    print("Waiting for receive something")
    packet = connection.stream_in_q.get()
    
    if packet != None:
        print("Packet received!:" + str(packet))
        checkPolicies(packet)

#this code won't be accessible, but for the sake of completeness
sh.teardown()

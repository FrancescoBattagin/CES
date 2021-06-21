#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
from scapy.all import *
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def checkPolicies(packet, p4info_helper, s1):
    #TODO db query, now managed as file.txt read
    policies = []
    with open("policiesDB.txt", 'r') as f:
        print("policiesDB.txt opened")
        line = f.readline()
        while line:
            policies.append(line.split(" "))
            line = f.readline()
    lookForPolicy(policies, packet, p4info_helper, s1)


def checkPoliciesDB(packet):
    policies = []
    try:
        with connect(
            host="localhost",
            user=input("Enter your username: "),
            password=input("Enter your password: "),
            database="Policydb"
        ) as connection:
            print(connection)
            prepared_statement = "SELECT * FROM policies"
            with connection.cursor() as cursor:
                cursor.execute(prepared_statement)
                policies = cursor.fetchall()
            print(policies)
            lookForPolicy(policies, packet)

    except Error as e:
        print(e)


def lookForPolicy(policyList, packet, p4info_helper, s1):
    found = False
    print("Policies: \n")
    print(policyList)
    src = packet[0][IP].src
    dst = packet[0][IP].dst
    if TCP in packet[0]:
            sport = packet[0][TCP].sport
            dport = packet[0][TCP].dport
    else
        sport = packet[0][TCP].sport
        dport = packet[0][UDP].dport
    for policy in policyList:
        for string in policy:
            if src in string and dst in string and dport in string: #sport not needed
                addEntries(packet[0][IP].dst, p4info_helper, s1)
                #add bi-directional entry if icmp packet!
                addEntries(packet[0][IP].src, p4info_helper, s1)
                found = True
                break
    if not found:
        #packet drop
        packet = None
        print("packet dropped")


def addEntries(ip, p4info_helper, s1):
    print("Inside addEntries")
    te = p4info_helper.buildTableEntry(
        table_name="my_ingress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ip
        },
        action_name="my_ingress.ipv4_forward",
        action_params={}
    )
    print("table entries defined")
    s1.WriteTableEntry(te)
    print("Installed leader table entry rule on ces")


def controller(switch): #, p4info_file_path, bmv2_file_path, ):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper("./advanced_tunnel.p4.p4info.txt")

    # Create a switch connection object for s1 and s2;
    # this is backed by a P4Runtime gRPC connection.
    # Also, dump all P4Runtime messages sent to switch to given txt files.
    s1 = switch
        #p4runtime_lib.bmv2.Bmv2SwitchConnection(
        #name='s1',
        #address='127.0.0.1:50051',
        #device_id=0,
        #proto_dump_file='logs/s1-p4runtime-requests.txt')

    # Send master arbitration update message to establish this controller as
    # master (required by P4Runtime before performing any other write operation)
    #s1.MasterArbitrationUpdate()

    # Install the P4 program on the switches
    #s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
    #print("Installed P4 Program using SetForwardingPipelineConfig on s1")

    while True:
        packet = None
        print("Waiting for receive something")

        packet = sniff(count = 1)

        print("Packet:")
        print(packet[0])

        fields = []
        print("Fields:")
        for field in packet[0]:
            fields.append(field)
        print(fields)
        
        if ICMP in packet[0] and str(packet[0][ICMP].type) == "8":
            print("PING from " + packet[0][IP].src)
            checkPolicies(packet, p4info_helper, s1)
        elif IP in packet[0]:
            print("Packet received!: " + packet[0][IP].src + "-->" + packet[0][IP].dst)
            checkPolicies(packet, p4info_helper, s1)
        else:
            print("No needed layer")

#if __name__ == '__main__':
def beg(switch):
    print("INSIDE BEG")
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()
    print("ARGS:")
    print(args)

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    controller(args.p4info, args.bmv2_json, switch)

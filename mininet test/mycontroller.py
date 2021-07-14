#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import p4runtime_sh.shell as sh
from p4runtime_sh.shell import PacketIn
from time import sleep
from scapy.all import *

def checkPolicies(pkt):
	#TODO db query, now managed as file.txt read
	policies = []
	with open("policiesDB.txt", 'r') as f:
		print("policiesDB.txt opened")
		line = f.readline()
		while line:
			policies.append(line.split(" "))
			line = f.readline()
	lookForPolicy(policies, pkt)


def checkPoliciesDB(pkt):
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
			lookForPolicy(policies, pkt)

	except Error as e:
		print(e)


def lookForPolicy(policyList, pkt):
	found = False
	print("Policies:")
	print(policyList)
	
	src = pkt.getlayer(IP).src
	dst = pkt.getlayer(IP).dst
	
	#pkt_tcp = pkt.getlayer(TCP)
	#pkt_udp = pkt.getlayer(UDP)
	#if pkt_tcp != None:
	#    print("protocol: TCP")
	#    sport = pkt_tcp.sport
	#    dport = pkt_tcp.dport
	#elif pkt_udp != None:
	#    print("protocol = UDP")
	#    sport = pkt_udp.sport
	#    dport = pkt_udp.dport
	#else:
	#	print("protocol unknown")
	print("src: " + src)
	print("dst: " + dst)
	#print("dport: " + str(dport))
	#print("sport: " + str(sport))
	for policy in policyList:
		if src in policy and dst in policy[1]:# and str(dport) in policy[2]:#src dst port; and dport in string: #sport not needed?                    
			addEntries(dst, src)#also dport and protocol
			#add bi-directional entry if icmp packet!
			if ICMP in packet and str(packet[ICMP].type) == "8":
				addEntries(src, dst)#also sport and protocol
			found = True
			break
	if not found:
		#packet drop
		packet = None
		print("packet dropped")


def addEntries(ip_dst, ip_src):#add port and protocol
	print("Inside addEntries")
	te = sh.TableEntry('my_ingress.ipv4_exact')(action='my_ingress.ipv4_forward')
	te.match["hdr.ipv4.dstAddr"] = ip_dst
	te.match["hdr.ipv4.srcAddr"] = ip_src
	#te.match["hdr.tcp.dstPort"] = port
	te.insert()
	print("[!] New entry added")


def packetHandler(streamMessageResponse):
	print("Packets received")
	packet = streamMessageResponse.packet

	if streamMessageResponse.WhichOneof('update') =='packet':
		packet_payload = packet.payload
		pkt = Ether(_pkt=packet_payload)
		if pkt.getlayer(IP) != None:
			pkt_src = pkt.getlayer(IP).src
			pkt_dst = pkt.getlayer(IP).dst
		ether_type = pkt.getlayer(Ether).type
		pkt_icmp = pkt.getlayer(ICMP)
		pkt_ip = pkt.getlayer(IP)

		if pkt_icmp != None and pkt_ip != None and str(pkt_icmp.getlayer(ICMP).type) == "8":
			print("PING from: " + pkt_src)
			checkPolicies(pkt)
		elif pkt_ip != None:
			print("Packet received!: " + pkt_src + "-->" + pkt_dst)
			checkPolicies(pkt)
		else:
			print("No needed layer (ARP, DNS, ...)")
	else:
		print("no")


def controller():

	sh.setup(
		device_id=0,
		grpc_addr='10.0.2.15:50051',
		election_id=(1, 0), # (high, low)
		config=sh.FwdPipeConfig('build/advanced_tunnel.p4.p4info.txt','build/advanced_tunnel.json')
	)

	#s1.MasterArbitrationUpdate()
	#s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)

	while True:
		packets = None
		print("Waiting for receive something")
		packet_in = sh.PacketIn()
		packets = packet_in.sniff(timeout=5)
		for streamMessageResponse in packets:
			packetHandler(streamMessageResponse)	

if __name__ == '__main__':
	controller()
	#parser = argparse.ArgumentParser(description='P4Runtime Controller')
	#parser.add_argument('--p4info', help='p4info proto in text format from p4c',
	#                    type=str, action="store", required=False,
	#                    default='./build/advanced_tunnel.p4.p4info.txt')
	#parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
	#                    type=str, action="store", required=False,
	#                    default='./build/advanced_tunnel.json')
	#args = parser.parse_args()
	
	#if not os.path.exists(args.p4info):
	#    parser.print_help()
	#    print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
	#    parser.exit(1)
	#if not os.path.exists(args.bmv2_json):
	#    parser.print_help()
	#    print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
	#    parser.exit(1)
	#controller()
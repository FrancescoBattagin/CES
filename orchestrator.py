#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.


#FIX THESE IMPORTS
# sys.path.append(
#     os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                  '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def printGrpcError(e):
    print("gRPC Error: " + e.details())
    status_code = e.code()
    print("(%s)" % status_code.name + sys.exc_info()[2])
    print("[%s : %d]" % traceback.tb_frame.f_code.co_filename + traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for switch;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        ces = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='CES',
            address='192.187.3.7:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        ces.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        ces.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on CES")


        # NEED TO "ACCEPT" ALL PACKETS TO TEST, WITHOUT TABLES
        receivePacketFromDataPlane()
        

        # Write the rules
        # writeTunnelRules(p4info_helper, ingress_sw=ces, egress_sw=ces, tunnel_id=100,
        #                  dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        # Print the tunnel counters every 2 seconds
        # while True:
        #     sleep(2)
        #     print '\n----- Reading tunnel counters -----'
        #     printCounter(p4info_helper, s, "MyIngress.ingressTunnelCounter", 100)
        #     printCounter(p4info_helper, s, "MyIngress.egressTunnelCounter", 100)

    except KeyboardInterrupt:
        print(" Shutting down.")
        ShutdownAllSwitchConnections()
    except grpc.RpcError as e:
        printGrpcError(e)
        ShutdownAllSwitchConnections()
    



#GitHub hints

#TOADD to p4 program?
# @controller_header("packet_in")
# header packet_in_t {
#     bit<9> ingress_port;
#     bit<7> padding;
# }

# @controller_header("packet_out")
# header packet_out_t {
#     bit<9> egress_port;
#     bit<7> padding;
# }


def receivePacketFromDataPlane():
    send_pkt.sendPacket('send_to_cpu') #?
    rep = sh.client.get_stream_packet('packet',timeout=2)
    if rep is not None:
        print('ingress port is %d' % int.from_bytes(rep.packet.metadata[0].value,'big'))
    

    #read from db/txt file
    policies = []
    with open("aaaaaa.txt", 'r') as f:
        line = f.readline()
        while line:
            policies.append(line.split(" "))
            line = f.readline()

    found = False
    #device_id = 
    #port =
    #desired_service =
    for policy in policies:
        if device_id in policy and port in policy and desired_service in policy: #&& desired info are present
            #forwarding
            sendPacketToDataPlane();
            found = True
            break
    if not found:
        #drop
        print("drop")


def sendPacketToDataPlane():
    pktInRaw = send_pkt.getPacktInRaw()
    req = p4runtime_pb2.StreamMessageRequest()
    packet = p4runtime_pb2.PacketOut()
    packet.payload = pktInRaw
    # another way to set packet field
    # packet = req.packet
    # packet.payload = pktInRaw


    metadata = p4runtime_pb2.PacketMetadata()
    #metadata = req.packet.metadata.add()
    metadata.metadata_id=1
    metadata.value = (1).to_bytes(2,'big')
    packet.metadata.append(metadata)
    #metadata = req.packet.metadata.add()
    metadata.metadata_id=2
    metadata.value = (0).to_bytes(2,'big')
    packet.metadata.append(metadata)
    req.packet.CopyFrom(packet)

    # another way to add metada fields, 
    # ref:https://developers.google.com/protocol-buffers/docs/reference/python-generated#repeated-fields
    sh.client.stream_out_q.put(req)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)

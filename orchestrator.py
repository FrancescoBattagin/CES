#!/usr/bin/env python2
import p4runtime_sh.shell as sh

def checkPolicies(packet):
    #read from db/txt file
    policies = []
    with open("policiesDB.txt", 'r') as f:
        line = f.readline()
        while line:
            policies.append(line.split(" "))
            line = f.readline()

    found = False
    for policy in policies:
        if device_id in policy and port in policy and desired_service in policy: #&& desired info are present
            found = True
            #connection.stream_out_q.put(packet)
            sendPacketToDataPlane()
            break
    if not found:
        #drop
        packet = None
        print("packet dropped")


def sendPacketToDataPlane():
    pktInRaw = send_pkt.getPacktInRaw()
    req = p4runtime_pb2.StreamMessageRequest()
    packet = p4runtime_pb2.PacketOut()
    packet.payload = pktInRaw
    
    metadata = req.packet.metadata.add()
    metadata.metadata_id=1
    metadata.value = (1).to_bytes(2,'big')
    metadata = req.packet.metadata.add()
    metadata.metadata_id=2
    metadata.value = (0).to_bytes(2,'big')
    packet.metadata.append(metadata)
    req.packet.CopyFrom(packet)

    sh.client.stream_out_q.put(req)


def receivePacketFromDataPlane():
    send_pkt.sendPacket('send_to_cpu')
    rep = sh.client.get_stream_packet('packet',timeout=2)
    if rep is not None:
        print('ingress port is',int.from_bytes(rep.packet.metadata[0].value,'big'))



sh.send_to_cpu(
    device_id=0,
    grpc_addr='192.187.3.7:50001',
    election_id=(0, 1), # (high, low)
    #config=sh.FwdPipeConfig('p4-test.p4info.txt', 'p4-test.json')
)

connection = sh.client

while True:
    packet = None
    print("Waiting for receive something")
    packet = connection.stream_in_q.get()
    
    if packet != None:
        print("Packet received!:" + str(packet))
        #CHECK POLICIES
        checkPolicies(packet)


#this code won't be accessible, but for the sake of completeness
sh.teardown()



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
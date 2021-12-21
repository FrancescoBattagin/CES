#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86dd;
#define CONTROLLER_PORT 255


/***HEADERS***/

typedef bit<48> EthernetAddress;
typedef bit<32> ip4Addr_t;
typedef bit<16>  egressSpec_t;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header packet_out_header_t {
    bit<16> egress_port;
}

header packet_in_header_t {
    bit<16> ingress_port;
}

struct metadata_t {

}

struct headers_t {
    packet_in_header_t  packet_in;
    packet_out_header_t packet_out;
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    ipv6_t           ipv6;
    tcp_t            tcp;
    udp_t            udp;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}


/***PARSER***/

parser my_parser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            TYPE_IPV6 : parse_ipv6;

        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/***CHECKSUM VERIFICATION***/

control my_verify_checksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { }
}


/***INGRESS***/

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*action ethernet_forward(EthernetAddress dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }*/

    action ipv4_forward(/*EthernetAddress dstAddr,*/ egressSpec_t port) {
        standard_metadata.egress_spec = port;
        /*ethernet_forward(dstAddr);*/
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv6_forward(/*EthernetAddress dstAddr,*/ egressSpec_t port){
        standard_metadata.egress_spec = port;
        /*ethernet_forward(dstAddr);*/
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;//This is similar to the ttl in ipv4, it time out when it is 0
    }

    action send_to_controller(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }


    table ipv4_tcp_open_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv4_tcp_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }


    table ipv4_udp_open_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv4_udp_forward {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.srcPort: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv6_tcp_open_forward {
        key = {
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            ipv6_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv6_tcp_forward {
        key = {
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            ipv6_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv6_udp_open_forward {
        key = {
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            ipv6_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table ipv6_udp_forward {
        key = {
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.udp.srcPort: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            ipv6_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()){
                ipv4_tcp_forward.apply();
            }
            else if (hdr.udp.isValid()){
                ipv4_udp_forward.apply();
            }
            else{ /*here to keep those tables even if non-used*/
                ipv4_tcp_open_forward.apply();
                ipv4_udp_open_forward.apply();
            }
        }
        else if (hdr.ipv6.isValid()){
            if (hdr.tcp.isValid()){
                ipv6_tcp_forward.apply();
            }
            else if (hdr.udp.isValid()){
                ipv6_udp_forward.apply();
            }
            else{ /*here to keep those tables even if non-used*/
                ipv6_tcp_open_forward.apply();
                ipv6_udp_open_forward.apply();
            }
        }
        else {
            send_to_controller();
        }
    }
}


/***EGRESS***/

control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}


/***CHECKSUM COMPUTATION***/

control my_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { }
}



/***DEPARSER***/

control my_deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.packet_out);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}


V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;
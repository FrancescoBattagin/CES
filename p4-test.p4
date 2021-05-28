#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_TUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
#define CONTROLLER_PORT 1


/***HEADERS***/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header tunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
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

struct metadata_t {

}

struct headers_t {
    ethernet_t   ethernet;
    tunnel_t     tunnel;
    ipv4_t       ipv4;
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
            TYPE_TUNNEL: parse_myTunnel;
            default : accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.tunnel);
        transition select(hdr.tunnel.proto_id){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action send_to_controller(){
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
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
    
    action tunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table tunnel_exact {
        key = {
            hdr.tunnel.dst_id: exact;
        }
        actions = {
            tunnel_forward;
            drop;
            send_to_controller;
            NoAction;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.tunnel.isValid()) {
            // Process only non-tunneled IPv4 packets
            ipv4_lpm.apply();
        }

        else if (hdr.tunnel.isValid()) {
            // process tunneled packets
            tunnel_exact.apply();
        }

        else
            send_to_controller();

        debug.apply();
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
    apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}



/***DEPARSER***/

control my_deparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.ipv4);
    }
}


V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;
#include "includes/headers.p4"
#include "includes/parser.p4"

#define TCP_HASH_BITS 13
#define IP_HASH_BITS 13
#define TCP_MAP_SIZE 8192  // 2^13
#define IP_MAP_SIZE 8192 // 2 ^ 13
#define PORT_SCAN_THRESHOLD 10

header_type ingress_metadata_t {
    fields {
        tcp_hash : TCP_HASH_BITS; // flowlet map index
        ip_hash: IP_HASH_BITS;
        last_seq_no: 32;
        is_syn: 1;
        is_rstack: 1;
        port_scan_count: 8;
    }
}

field_list l3_syn_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    ipv4.protocol;
}

field_list_calculation tcp_syn_hash_spec {
    input {
        l3_syn_hash_fields;
    }
    algorithm: crc16;
    output_width: TCP_HASH_BITS;
}

field_list ip_hash_fields {
    ipv4.dstAddr;
    ipv4.srcAddr;
    ipv4.protocol;
}

field_list_calculation ip_hash_spec {
    input {
        ip_hash_fields;
    }
    algorithm: crc16;
    output_width: IP_HASH_BITS;
}

field_list l3_rstack_hash_fields {
    ipv4.dstAddr;
    ipv4.srcAddr;
    tcp.dstPort;
    tcp.srcPort;
    ipv4.protocol;
}

field_list_calculation tcp_rstack_hash_spec {
    input {
        l3_rstack_hash_fields;
    }
    algorithm: crc16;
    output_width: TCP_HASH_BITS;
}

register seqno_registers {
    width : 32; // should store the seq number
    instance_count : 8192;
}

register port_scan_count_registers {
    width : 8;
    instance_count: 8192;
}

register debug_registers {
    width: 32;
    instance_count: 10;
}

metadata ingress_metadata_t ingress_metadata;

action _drop() {
    drop();
}

counter tcp_packet_type_counter {
    type: packets;
    static: tcp_packet_type;
    instance_count: 2;
}

table tcp_packet_type {
    reads {
        tcp.ctrl: exact;
    }
    actions {
        on_syn;
        on_rstack;
        // TODO cleanup state if not syn or rst_ack
        // doesnt_matter;
        _drop;
    }
    size: 3;
}

table port_scan_counts {
    actions {
        increment_port_scan_count;
    }
    size: 1;
}

action increment_port_scan_count() {
    modify_field_with_hash_based_offset(ingress_metadata.ip_hash, 0,
        ip_hash_spec, IP_MAP_SIZE);

    register_read(ingress_metadata.port_scan_count,
        port_scan_count_registers, ingress_metadata.ip_hash);

    add_to_field(ingress_metadata.port_scan_count, 1);

    register_write(port_scan_count_registers, ingress_metadata.ip_hash,
        ingress_metadata.port_scan_count);

    register_write(debug_registers, 2, ingress_metadata.ip_hash);
}


action on_syn() {
    modify_field_with_hash_based_offset(ingress_metadata.tcp_hash, 0,
        tcp_syn_hash_spec, TCP_MAP_SIZE);

    register_write(debug_registers, 0, ingress_metadata.tcp_hash);

    register_write(seqno_registers, ingress_metadata.tcp_hash, tcp.seqNo);
    add_to_field(ingress_metadata.is_syn, 1);

    count(tcp_packet_type_counter, 0);
    modify_field(standard_metadata.egress_spec, 2);
}

action on_rstack() {
    modify_field(ingress_metadata.is_rstack, 1);
    modify_field_with_hash_based_offset(ingress_metadata.tcp_hash, 0,
        tcp_rstack_hash_spec, TCP_MAP_SIZE);

    register_write(debug_registers, 1, ingress_metadata.tcp_hash);

    register_read(ingress_metadata.last_seq_no,
        seqno_registers, ingress_metadata.tcp_hash);

    add_to_field(ingress_metadata.last_seq_no, 1);

    count(tcp_packet_type_counter, 1);
    modify_field(standard_metadata.egress_spec, 1);
}

action debug_counter_incr() {
    count(debug_counter, 0);
}

table debug_counter_table {
    actions { debug_counter_incr; }
    size: 1;
}

counter debug_counter {
    type: packets;
    static: debug_counter_table;
    instance_count: 1;
}

control ingress {
    apply(tcp_packet_type);
    if (ingress_metadata.is_syn == 1) {
        // apply(forward);
    }
    
    else if (ingress_metadata.is_rstack == 1) {
        if (ingress_metadata.last_seq_no == tcp.ackNo) {
            apply(port_scan_counts);

            if (ingress_metadata.port_scan_count > PORT_SCAN_THRESHOLD) {
                apply(debug_counter_table);
            }
        }
    }
}

control egress {
}

// 14 Bytes
header_type ethernet_t {
  fields {
  dstAddr : 48;
  srcAddr : 48;
  etherType : 16;
  }
}

// 8 Bytes
header_type arp_t {
  fields {
  htype	: 16;
  ptype	: 16;
  hlen	:  8;
  plen	:  8;
  oper	: 16;
  }
}

// 20 Bytes
header_type arp_ipv4_t {
  fields {
  sha : 48;
  spa : 32;
  tha : 48;
  tpa : 32;
  }
}

header_type bro_t {
  fields {
  event: 16;
  }
}

header ethernet_t eth_head;
header arp_t arp_head;
header arp_ipv4_t arp_ipv4;
header bro_t bro_header;

parser start {
  return parse_eth;
}

parser parse_eth {
  extract(eth_head);
  return select(latest.etherType){
  0: dummy;
  default: parse_arp;
  }
}

parser parse_arp {
  extract(arp_head);
  return parse_arp_ipv4;
}

parser parse_arp_ipv4 {
  extract(arp_ipv4);
  return ingress;
}

parser dummy {
  extract(bro_header);
  return parse_arp;
}

counter request_indirect_counter {
  type: packets;
  static: arp_request_packet;
  instance_count: 1;
}

counter reply_indirect_counter {
  type: packets;
  static: arp_reply_packet;
  instance_count: 1;
}

counter corrupted_counter {
  type: packets;
  static: corrupted_packet_table;
  instance_count: 1;
}

action count_request_packet() {
  add_header(bro_header);
  modify_field(bro_header.event, 3);
  modify_field(eth_head.etherType, 0x4444);
  count(request_indirect_counter, 0);
  modify_field(standard_metadata.egress_spec, 2);
}

action count_reply_packet() {
  add_header(bro_header);
  modify_field(bro_header.event, 4);
  modify_field(eth_head.etherType, 0x4444);
  count(reply_indirect_counter, 0);
  modify_field(standard_metadata.egress_spec, 2);
}

action count_corrupted_packet() {
  add_header(bro_header);
  modify_field(bro_header.event, 1);
  modify_field(eth_head.etherType, 0x4444);
  count(corrupted_counter, 0);
  modify_field(standard_metadata.egress_spec, 2);
}

table arp_request_packet {
  actions {
    count_request_packet;
  }
  size: 1;
}

table arp_reply_packet {
  actions {
    count_reply_packet;
  }
  size: 1;
}

table corrupted_packet_table {
  actions {
    count_corrupted_packet;
  }
  size: 1;
}

control ingress {
  if (standard_metadata.packet_length - 14 < 28) {
    // Do modifications for Corrupted packets and drop the packet here
    apply(corrupted_packet_table);
  } else if (arp_head.oper == 1 ) {
    // Do modifications for request event here
    apply(arp_request_packet);
  } else if (arp_head.oper == 2 ) {
    // Do modifications for reply event here
    apply(arp_reply_packet);
  } else {
    // Nothing
  }
}

control egress {
  // leave empty
}

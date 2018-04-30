#!/usr/bin/python

import sys
from scapy.all import sendp, rdpcap

def main():
    pcap = rdpcap(sys.argv[1])
    req_or_reply = sys.argv[2]
    if (req_or_reply not in ("req", "rep")):
        print "thu"
        return

    # 2 pkts request and reply
    pkts = [ pkt for pkt in pcap ]
    get_request_pkt = lambda: pkts[0]
    get_reply_pkt = lambda: pkts[1]

    pkt = None
    if (req_or_reply == "req") :
        pkt = get_request_pkt()
    else:
        pkt = get_reply_pkt()

    print pkt.show()
    sendp(pkt, iface = "eth0")

if __name__ == '__main__':
    main()

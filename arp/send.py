#!/usr/bin/python

from scapy.all import sniff, sendp
from struct import pack

def main():
    while(1):
        bcast_mac = pack('!6B', *(0xFF,)*6)
        socket_mac = pack('!6B', 0x56, 0xD0, 0x59, 0x8E, 0x20, 0x60)
        ETHERNET_PROTOCOL_TYPE_ARP = pack('!H', 0x0806)
        ARP_PROTOCOL_TYPE_ETHERNET_IP = pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004)
        ARPOP_REQUEST = pack('!H', 0x0001)
        ARPOP_REPLY = pack('!H', 0x0002)
        arpop = ARPOP_REQUEST
        sender_mac = pack('!6B', *(0x11,)*6)
        ip = "10.0.0.1"
        sender_ip = pack('!4B', *[int(x) for x in ip.split('.')])
        target_mac = pack('!6B', *(0x22,)*6)
        ip = "10.0.0.2"
        target_ip = pack('!4B', *[int(x) for x in ip.split('.')])
        
        print("Select ARP packet")
        print("1. ARP Request")
        print("2. ARP Reply")
        print("3. Truncated ARP")
        type = input("What do you want to send: ")
        if type == 1:
            arpop = ARPOP_REQUEST
        elif type == 2:
            arpop = ARPOP_REPLY
        elif type == 3:
            print "Sending truncated ARP"
        else:
            continue
        arpframe = [
            # ## ETHERNET
            # destination MAC addr
            bcast_mac,
            # source MAC addr
            socket_mac,
            ETHERNET_PROTOCOL_TYPE_ARP,
            
            # ## ARP
            ARP_PROTOCOL_TYPE_ETHERNET_IP,
            # operation type
            arpop,
            # sender MAC addr
            sender_mac,
            # sender IP addr
            sender_ip,
            # target hardware addr
            target_mac,
            # target IP addr
            target_ip
        ]

        if type == 3:
            arpframe = arpframe[:-1]
        # send the ARP
        sendp(''.join(arpframe), iface = "eth0")

if __name__ == '__main__':
    main()

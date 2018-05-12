# Offloading computation from BRO onto a P4 enabled switch

[Bro](https://github.com/bro/bro/) is an Intrusion Detection System that listens on a host interface.
This project aims to offload some of its event detection logic onto a [P4](https://p4.org/) enabled switch.
The arp folder contains P4 code that detects different ARP events and indicates detection using counters.
The portscan folder contains P4 code that detects a single host portscan and sends a packet with a custom header to bro.
The bro folder contains the changes to Bro to read the new custom header and raise the right event based on the event type.

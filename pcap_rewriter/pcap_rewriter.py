#!/usr/bin/env python

import argparse
import textwrap
from scapy.all import *

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
                    pcap_rewriter.py
                Brought to you by:
                    @da_667
                Original Script by:
                    @catalyst256
                ---------------------
Rewrite source and destination IP addresses as well as IP and TCP checksums in a target pcap
Usage: pcap_rewrite.py -i <infile.pcap> -o <outfile.pcap> -s <source_IP> -d <destination_IP>
'''))

#infile, outfile, source IP and dest IP arguments via ArgParse are all required.

parser.add_argument('-i', dest="infile", required=True,
                    help="The name of your source PCAP file.")
parser.add_argument('-o', dest="outfile", required=True, help="The name of the file you would like to write your new PCAP to.")
parser.add_argument('-s', dest="s_ip", required=True, help="The source IP address you would like to replace")
parser.add_argument('-d', dest="d_ip", required=True, help="The destination IP address you would like to replace")
args = parser.parse_args()


pcap = args.infile
s_ip = args.s_ip
d_ip = args.d_ip
outfile = args.outfile
pkts = rdpcap(pcap)

# Find the first packet and use that as the reference for source and destination IP address
sip = pkts[0][IP].src
dip = pkts[0][IP].dst

print ('[!] The address of ' + sip + ' will be overwritten with ' + s_ip)
print ('[!] The address of ' + dip + ' will be overwritten with ' + d_ip)

# Delete the IP and TCP checksums so that they are recreated when we change the IP addresses
print ('[-] Deleting old checksums so that scapy will regenerate them correctly')
for p in pkts:
	del p[IP].chksum
	del p[TCP].chksum

# Rewrite the packets with the new addresses
print ('[-] Rewriting source and destination IP addresses')
for p in pkts:
	if p.haslayer(IP):
		if p[IP].src == sip:
			p[IP].src = s_ip
			p[IP].dst = d_ip
			# print p[IP].dst
		if p[IP].dst == sip:
			p[IP].src = d_ip
			p[IP].dst = s_ip

# Write the packets out to a new file
print ('[!] Writing out pkts to new file ' + outfile)
wrpcap(outfile, pkts)

print ('[!] All done!!!')
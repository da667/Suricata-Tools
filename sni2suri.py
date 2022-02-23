#!/usr/bin/env python3
# Version 1.0
##Imports##
#Argparse for fancy cli args
#textwrap for a fancy help/description output
#datetime for "created_at" timestamp metadata

import argparse
import datetime
import re
import textwrap

#Initialize argparse and print the big description and help usage block if -h or --help is used

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
                    sni2suri.py
                Brought to you by:
                    @da_667
                ---------------------
Generates suricata TLS rules from a list of TLS SNIs/Hostnames.
Usage: sni2suri.py -i <infile> -o <outfile> -s 1000000
Infile format:
www.evil.com
Outfile format:
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious Domain (www .evil .com) in TLS SNI"; flow:established,to_server; tls.sni; content:"www.evil.com"; nocase; bsize:12; fast_pattern; classtype:misc-activity; sid:1000000; rev:1; metadata: created_at 2022_02_23, deployment Perimeter;)
'''))

#infile, outfile, and sid arguments via ArgParse are all required.

parser.add_argument('-i', dest="infile", required=True,
                    help="The name of the file containing a list of Domains, One domain per line.")
parser.add_argument('-o', dest="outfile", required=True, help="The name of the file to output your suricata rules to.")
parser.add_argument('-s', dest="sid", type=int, required=True,
                    help="The suricata sid to start numbering incrementally at. This number should be between 1000000-1999999")
args = parser.parse_args()

#This is a small check to ensure -s is set to a valid value between 1000000-1999999 - the local rules range. According to: https://sidallocation.org/

if args.sid < 1000000:
    print ("The Value for sid (-s) is less than 1000000.")
    exit()
elif args.sid > 1999999:
    print ("The Value for sid (-s) is greater than 1999999.")
    exit()

#use datetime to establish the current year, month, and date for the created_at rule metadata
now = datetime.date.today()
ts_createdat = now.strftime("%Y_%m_%d")

#This is the substring we're gonna look for on each line to determine whether or not to create a TLS SNI rule for all subdomains of the SNI string, or just that specific SNI.
endswith = ",e"

'''
fout is the file we will be outputting our rules to.
f is the file we will read a list of domains from.
This script iterates through each line (via for line loop).
If the line is empty or contains an octothorpe (#) ignore it.
If there is deadspace on the line that could cause problems with the suricata rule, strip it out.
We generate one of two types of rules, depending on whether or not the line contains ",e":
The first type of rule utilizes endswith to hunt for any subdomains of the SNI specified. For example subject alternate names, etc.
The second type of rule does an exact content match, and uses bsize to ensure that ONLY the provided SNI matches the rule.
For the msg portion of the rule, use the re module to insert a space in front of each period for the domain, in order to "sanitize" the message the alert produces
If the user is generating a type 1 rule, we also use the re module to strip out the ",e" for the rule message.
'''

with open(args.outfile, 'w') as fout:
    with open(args.infile, 'r') as f:
        for line in f:
            if line.strip():
                sni = line.strip()
                if sni.startswith('#'):
                    continue
                if endswith in sni:
                    sni = re.sub(',e', '', sni, flags=re.IGNORECASE)
                    msg = re.sub('\.', ' .', sni)
                    rule = ("alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious Domain (%s) in TLS SNI\"; flow:established,to_server; tls.sni; content:\"%s\"; endswith; nocase; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (msg, sni, args.sid, ts_createdat))
                else:
                    msg = re.sub('\.', ' .', sni)
                    rule = ("alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious Domain (%s) in TLS SNI\"; flow:established,to_server; tls.sni; content:\"%s\"; nocase; bsize:%s; fast_pattern; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (msg, sni, len(sni), args.sid, ts_createdat))
                fout.write(rule)
                print (rule)
                args.sid += 1
exit()
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
                    dns2snort.py
                Brought to you by:
                    @da_667
                With Special Thanks from:
                    @botnet_hunter
                     @3XPlo1T2
                ---------------------
Generates suricata DNS rules from a list of domains.
Usage: dns2rule.py -i <infile> -o <outfile> -s 9000000
Infile format:
www.evil.com
Outfile format:
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious DNS Lookup (www.evil.com)"; dns.query; content:"www.evil.com" nocase; bsize:12; classtype:misc-activity; sid:9000000; rev:1; metadata: created_at 2022_22_02, deployment Perimeter;)
'''))

#Infile, outfile, and sid arguments via ArgParse are all required.

parser.add_argument('-i', dest="infile", required=True,
                    help="The name of the file containing a list of Domains, One domain per line.")
parser.add_argument('-o', dest="outfile", required=True, help="The name of the file to output your suricata rules to.")
parser.add_argument('-s', dest="sid", type=int, required=True,
                    help="The suricata sid to start numbering incrementally at. This number should be between 9000000-9999999")
parser.add_argument('-w', dest="www", required=False, action='store_true', help="Remove the 'www' subdomain from domains that have it. This will apply the \"dotprefix;\" AND \"endswith;\" modifiers to all domains beginning with \"www\"")
args = parser.parse_args()

#This is a small check to ensure -s is set to a valid value between 9000000-9999999 - the local rules range.

if args.sid < 9000000:
    print ("The Value for sid (-s) is less than 9000000.")
    exit()
elif args.sid > 9999999:
    print ("The Value for sid (-s) is greater than 9999999.")
    exit()

#use datetime to establish the current year, month, and date for the created_at rule metadata
now = datetime.date.today()
ts_createdat = now.strftime("%Y_%m_%d")

#fout is the file we will be outputting our rules to.
#f is the file we will read a list of domains from.
#This script iterates through each line (via for line loop) and splits on periods (.), creating a list for each line.
#The script calculates the segments of the domain in question (can handle 1-4 segments -- e.g. .ru (1 segments, TLD) all the way to this.is.evil.ru (4 segments))
#Each segment of a domain has it's string length calculated and converted to hex.
#If the segment is less than or equal to 0xf, this is converted to "0f" (padded with a zero, since snort rules expect this)
#The hexidecmal letter is converted to upper case, and the rule is written to a file.
#after the rule is written the SID number is incremented by 1 for the next rule.

with open(args.outfile, 'w') as fout:
    with open(args.infile, 'r') as f:
        for line in f:
            if line.strip():
                domain = line.strip()
                if domain.startswith('#'):
                    continue
                if args.www == True: 
                    domain = re.sub('^www', '', domain, flags=re.IGNORECASE)
                if domain.startswith('.'):
                    rule = ("alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious DNS Lookup (%s)\"; dns.query; dotprefix; content:\"%s\" nocase; endswith; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (domain, domain, args.sid, ts_createdat))
                else:
                    rule = ("alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious DNS Lookup (%s)\"; dns.query; content:\"%s\" nocase; bsize:%s; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (domain, domain, len(domain), args.sid, ts_createdat))
                fout.write(rule)
                print (rule)
                args.sid += 1
exit()
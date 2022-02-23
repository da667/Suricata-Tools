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
                    dns2suri.py
                Brought to you by:
                    @da_667
                With Special Thanks from:
                    @botnet_hunter
                     @3XPlo1T2
                ---------------------
Generates suricata DNS rules from a list of domains.
Usage: dns2suri.py [-w] -i <infile> -o <outfile> -s 9000000
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
#This script iterates through each line (via for line loop).
#If the line is empty or contains an octothorpe (#) ignore it.
#If there is deadspace on the line that could cause problems with the suricata rule, strip it out.
#For the msg portion of the rule, use the re module to insert a space in front of each period for the domain, in order to "sanitize" the message the alert produces to not cause more false positives on accident.
#If the user invoked the -w option, strip out the 'www' portion of the domain they specified. 
#We generate one of two types of rules, depending on if the first character of the domain begins with a period (.)
#The first type of rule utilizes dotprefix and endswith to hunt for any subdomains of the domain specified.
#The second type of rule does an exact content match, and uses bsize to ensure that ONLY that domain matches the rule.

with open(args.outfile, 'w') as fout:
    with open(args.infile, 'r') as f:
        for line in f:
            if line.strip():
                domain = line.strip()
                if domain.startswith('#'):
                    continue
                if args.www == True: 
                    domain = re.sub('^www', '', domain, flags=re.IGNORECASE)
                msg = re.sub('\.', ' .', domain)
                if domain.startswith('.'):
                    rule = ("alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious DNS Lookup (%s)\"; dns.query; dotprefix; content:\"%s\" nocase; endswith; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (msg, domain, args.sid, ts_createdat))
                else:
                    rule = ("alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:\"Suspicious DNS Lookup (%s)\"; dns.query; content:\"%s\" nocase; bsize:%s; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)" % (msg, domain, len(domain), args.sid, ts_createdat))
                fout.write(rule)
                print (rule)
                args.sid += 1
exit()
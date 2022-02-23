# Suricata-Tools : Secret Weapons of the Cyberwar

Hey hey people, Welcome to another one of my use~less~ful github projects. Suricata-Tools is a repo containing a bunch of bite-sized python scripts to make various aspects of managing suricata a little bit easier to deal with. For right now, the repo is small, but as I add additional scripts and tools that help me to do my job, I'll probably contribute more code to it.

## Prereqs/Supported Operating Systems

Hypothetically, these tools /should/ run on anything that has a python3 interpreter, and for now, external dependencies are minimal because I'm bad a python, and therefore my scripts need to be kept simple.

## The Toolkit

### dns2suri.py

A python script that will take a newline separated list of DNS domains and spit out suricata DNS rules.

#### Usage:
dns2suri has three required arguments, and two optional arguments:
- `-i`. **Required** argument. Defines input file. Tells dns2suri where the file containing your list of newline delimited DNS domains are located. Please be aware that dns2suri is capable of detecting and skipping both blank lines with no content, and comment lines that start with the octothorpe (#).
- `-o`. **Required** argument. Defines output file. Tells dns2suri where to write your Suricata DNS rules.
- `-s`. **Required** argument. Defines the suricata SID number to start numbering your rules from. Please select a sid from 1000000 - 1999999 to avoid SID number conflicts.
- `-w`. Optional argument. Tells dns2suri to strip out 'www' from all DNS domains contained in the specified input file. For example, if your input file includes "www.youtube.com" dns2suri will create a rule for ".youtube.com", applying both the `dotprefix;` and `endswith;` modifiers, creating a rule that will hunt for subdomains of youtube.com such as a.youtube.com, b.youtube.com, etc.
- `-h`. Optional argument. Displays help output.

#### Other documentation:
- If you specify an output file that already exists with the `-o` option, dns2suri will overwrite it, without preserving it.
- dns2suri provides two DNS rule templates, based on whether or not the domain begins with a "." or not:

```
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious DNS Lookup (%s)"; dns.query; dotprefix; content:"%s" nocase; endswith; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)
```
This rule format is meant to produce DNS rules that begin with a period (.) and are designed to hunt for sub-domains of the domain name specified. For example, if one of the lines in your input file (`-i`) contains ".4chan.org", This is the rule that would get generated:

```
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious DNS Lookup (.4chan.org)"; dns.query; dotprefix; content:".4chan.org" nocase; endswith; classtype:misc-activity; sid:1000000; rev:1; metadata: created_at 2022_02_22, deployment Perimeter;)
```

Hypothetically, this will match on:

www.4chan.org
boards.4chan.org

...and any other subdomain of 4chan.org. Thanks to the `dotprefix;` option, the rule will match on JUST subdomains of ".4chan.org", instead of say, "chan4chan.org" while the `endswith;` option ensures that every dns domain that this rule matches is a subdomain of 4chan.org. If this doesn't make any sense, Take a look at the OISF documentation here:

dotprefix: https://suricata.readthedocs.io/en/suricata-6.0.4/rules/transforms.html?highlight=dotprefix#dotprefix
endswith: https://suricata.readthedocs.io/en/suricata-6.0.4/rules/payload-keywords.html?highlight=endswith#endswith

The OTHER rule template dns2suri generates looks like this:

```
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious DNS Lookup (%s)"; dns.query; content:"%s" nocase; bsize:%s; classtype:misc-activity; sid:%s; rev:1; metadata: created_at %s, deployment Perimeter;)
```

This DNS rule template with provide an EXACT match on the DNS domain specified in the intput file. For example, the domain "www.youtube.com" will generate the following rule:

```
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious DNS Lookup (www.youtube.com)"; dns.query; content:"www.youtube.com" nocase; bsize:15; classtype:misc-activity; sid:1000000; rev:1; metadata: created_at 2022_02_22, deployment Perimeter;)
```

Again, this rule will match on JUST the domain www.youtube.com. This is thanks to the `bsize` modifier. If you wanna know more about bsize, check out the read the docs info here:

bsize: https://suricata.readthedocs.io/en/suricata-6.0.4/rules/payload-keywords.html?highlight=bsize#bsize

- As mentioned above, the `-w` option strips 'www' out of domains in the input file. Leaving behind ".blah.com". Meaning that dns2suri will ALWAYS produce the first type of DNS rule temple for any domains starting with 'www' if the `-w` option is used.
- dns2suri is capable of skipping empty lines, skipping comment lines that contain an octothorpe (#) and is capable of stripping out excess spaces on the lines containing your domains. So for example if your file contained:

```
#ayy lmao
      .blob.core.windows.net      
	  
reddit.com



www.youtube.com    

#another comment, lol
   www.yeettheayys.cf   

```

dns2suri will normalize it to:

```
.blob.core.windows.net
reddit.com
www.youtube.com
www.yeettheayys.cf
```
...and create the proper DNS rules for the domains provided.

## Acknowledgements

dns2suri is heavily based on my (very) old dns2snort python script from way back in the day. I had significant help from @botnet_hunter and @3XPlo1T2. I also cribbed heavily off of the emerging threats DNS rules on the ET_OPEN rule feed to create my DNS rule templates, so shoutout to proofpoint ET_LABS. Finally, big thanks to OISF and their very meticulously documented "read the docs" site detailing pretty much everything you need to know about every Suricata rule option imaginable.

## Licensing

dns2suri is provided under MIT Licensing. Other tools added to this repo TBD.

## Patch Notes
- 2022-02-23
	- Realized that the msg portion of the rule should probably contain a "defanged" version of the domain, so I used some regex to insert a space in front of each period for each portion of a provided domain to make things a little bit safer.
	- Changed the SID range from 9000000-9999999 to 1000000-1999999 as this is the SID range reserved for local rules according to https://sidallocation.org/
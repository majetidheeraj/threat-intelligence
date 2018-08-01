# threat-intelligence
Gathering STIX 2.0 Threat Intelligence feeds from X-force Threat Exchange


C:\Users\Dheeraj\threat-intelligence>cybersecurityproject.py -h
usage: cybersecurityproject.py [-h] [--search SEARCH] [--hash HASH] [--ip IP]
                               [--whois WHOIS] [--iprep IPREP]
                               [--vulninfo VULNINFO] [--latestvuln]
                               [--cve CVE] [--urlmalware URLMALWARE]
                               [--dnsinfo DNSINFO]

optional arguments:
  -h, --help            show this help message and exit
  --search SEARCH       Query any items(virus/malware etc)
  --hash HASH           Get Malware for file hash
  --ip IP               Get IP by category
  --whois WHOIS         Get who is information
  --iprep IPREP         Get IP reputation
  --vulninfo VULNINFO   Search Vulnerability Information
  --latestvuln          Get Recent Vulnerability Information
  --cve CVE             Get information based on cve
  --urlmalware URLMALWARE
                        Returns the malware associated with the entered URL
  --dnsinfo DNSINFO     Get DNS Records for IP

The above options gather the threat information in JSON format and writes to a file.

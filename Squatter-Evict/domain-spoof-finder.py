"""
domain-spoof-finder.py
v1
Written by Aaron White, UCSC
=====
This script takes a domain as input and runs it through the DNSTwister fuzz API to get a list of 
fuzzed domain names. These domains are then filtered for only those that are actual live domains.
The resulting list is checked against MISP for any intel hits. If any domains match, they are rpz'd.
Finally, an email is sent to a chosen recipient.

"""


import sys
import os
import requests
from pymisp import PyMISP
import rpz
import smtplib, ssl
from creds import *

#MISP variables
misp_url = "https://"
misp_key = MISP_AUTH_KEY
ssl = "True"

#create MISP client object
misp = PyMISP(misp_url, misp_key, ssl, debug=False)

#instantiate list to add discovered live domains to
domains = []

#fuzz for similar domain names and filter out domains that do not resolve to an IP addres
   
def get_domains(domain):
    print(domain)
    print(type(domain))
    
    hex_domain = str(requests.get("https://dnstwister.report/api/to_hex/" + domain).json()["domain_as_hexadecimal"])
    
    r = requests.get("https://dnstwister.report/api/fuzz/" + hex_domain).json()

    for i in r["fuzzy_domains"]:
        x = i["resolve_ip_url"]
        rr = (requests.get(x).json())
        if rr["ip"] == False:
            continue
        else:
             domains.append(i["domain"])
    print(domains)
    
get_domains(sys.argv[1])

#Take list of domains and check against MD threat intel

live_domains = []

def intel_check(domains):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    for i in domains:
        r = misp.search(controller='attributes', type_attribute=['hostname'], value= i)
        if r.get('Attribute') == []:
            print('no matching event found')
        else:
            rpz.add_rpz(i, 'typo_squatter-' + datetime.today().strftime('%Y-%m-%d'))
            live_domains.append(i)

#Email the results

smtp_server = "smtp.blah.com"
port = 465
password = 
sender = "blah@blah.com"
receiver = "blah@blah.com"

context = ssl.create_default_context()

with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
    server.login(sender, password)
    server.sendmail(sender, receiver, live_domains)

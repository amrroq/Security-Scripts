import requests
import tldextract
import json

# Local imports
from creds import *

# Get username and password for auth #
wapi_session = requests.session()
wapi_session.auth = ('user', 'passwd')

rpz_redirect= "*."
rpz_zone="rpz-local-rewrite"
rtbh_duration=2592000
url=""


def add_dns_record(record,reason):
  payload = '{"name":"'+record+'","canonical":"'+rpz_redirect+'","comment":"'+reason+'","rp_zone":"'+rpz_zone+'"}'
  headers = { 'content-type': "application/json" }
  #for debug
  #print(payload)
  # WAPI call POST /record:host #
  response = wapi_session.post(url+"?_return_as_object=1", data=payload,
  headers=headers, auth=(hostmaster_user, hostmaster_pass), verify=True)

  if response.status_code == 201:
      print(f"Success: {json.loads(response.text)}.")
  else:
      print(f"Failed: {json.loads(response.text)['text']}.")



def add_rpz(domain,reason):
  #set up globals for ease of edits
  global wapi_session
  global rpz_redirect
  global hostmaster_user
  global hostmaster_pass
  global url
  global rpz_zone

  print (f"add_rpz:({domain},{reason})")
  #strip domain to soa
  #leaving code for now but will not block tld for various reasons.
  domain_ext = tldextract.extract(domain)
  #domaintoblock= domain_ext.domain+domain_ext.suffix
  #The following line will strip to the tld and block which is bad for shared services/domains
  #domaintoblock= domain_ext.domain+ "."+domain_ext.suffix

  #setup records for insert
  block_record = f"{domain}.{rpz_zone}"
  wildcard_record= f"*.{domain}.{rpz_zone}"
  #print (f"block record is {block_record}")
  #print (f"wildcard record is {wildcard_record}")

  ### block original record
  add_dns_record(block_record,reason)

  ### block wildcard record
  add_dns_record(wildcard_record,reason)

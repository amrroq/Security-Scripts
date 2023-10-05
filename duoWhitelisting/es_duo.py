"""
es_duo.py
v1
Written by Aaron White, UCSC
=====
This script collects IP addresses that have successfully authenticated using duo and automatically imports those IPs into the BHR whitelist table.

Users provide Elasticsearch credentials by setting the ESUSER and ESPASS environment variables
Users provide their unique BHR API token by setting the BHRTOKEN environment variable.

example usage:
es_duo.py <search from this date> <search to this date> -s <optional size paramater: maximum number of duo records to return and then import as whitelist records (default is 1000)>

>$ python3 es_duo.py 2020-06-10T12:30:00Z 2020-06-10T13:30:00Z -s 10
/Users/abwhite/Library/Python/3.7/lib/python/site-packages/elasticsearch/connection/http_urllib3.py:197: UserWarning: Connecting to itsec-prod-velk-1.ucsc.edu using SSL with verify_certs=False is insecure.
  % host
IPs retrieved: 10
6  IPs were successfully added as whitelist entries
4  campus IPs were pruned


"""

from elasticsearch import Elasticsearch
from bhr_client.rest import login
import os
import re
from datetime import datetime
import requests
import urllib3
from netaddr import *
import argparse

#Import elastic credentials from environment variables
es_user = os.environ.get('ESUSER')
es_pass = os.environ.get('ESPASS')

if not es_user:
 raise Exception("Please provide an elasticsearch username by setting the ESUSER environment variable")

if not es_pass:
 raise Exception("Please provide an elasticsearch password by setting the ESPASS environment variable")

#Set es connection/query variables
es_host = ""
es_index= ""
src_ip = "srcip"    #this field name could change later in elasticsearch, so it is set as a variable for this script


#Set bhr url and auth header values and create authenticated bhr_client object
bhr_url = "https://"
bhr_whitelist_url = "https://../bhr/api/whitelist/"
bhr_token = os.environ.get('BHRTOKEN')
bhr_headers = {"Authorization" : "Token " + bhr_token}
bhr_client = login(bhr_url, token=bhr_token, ssl_no_verify=True) 

#Define campus networks
campus_lan = IPNetwork("128.114.0.0/16")
eduroam = IPNetwork("169.233.0.0/16")

#Disable insecure connection/cert verification warnings
urllib3.disable_warnings()

#Command line arguments
parser = argparse.ArgumentParser()

parser.add_argument('fromdate', help='provide an end date/time for the query | format is yyyy-MM-ddTHH:mm:ssZ')
parser.add_argument('todate', help='provide a start date/time for the query | format is yyyyMMddTHHmmssZ')
parser.add_argument('-s', '--size', default=1000, help='maximum number of duo records to return and then import (default is 1000)')

args = parser.parse_args()

#Elasticsearch host connection
es = Elasticsearch(
    [es_host],
    http_auth=(es_user, es_pass),
    use_ssl=True,
    verify_certs=False,
)

#Build the query
query = {
  "_source": {
    "includes": [src_ip]
  },
  "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "match_all": {}
        },
        {
          "match_phrase": {
            "event_type": "authentication"
          }
        },
        {
          "match_phrase": {
            "result": "success"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": args.fromdate,
              "lte": args.todate,
            }
          }
        }
        ],
      "should": [],
      "must_not": []
    }
  }
}

#Make the query    
res = es.search(index=es_index, size=args.size, body=query)

if len(res['hits']['hits']) == 0:
 raise Exception("No records returned")

if len(res['hits']['hits']) < int(args.size):
  raise Exception("The number of records retrieved was less than the number specified in the size (-s) optional parameter. Consider widening your search time frame to retrieve more records")

print("IPs retrieved: " + str(len(res['hits']['hits'])))

#Create a list of unique IPs from the es query results, filtering out campus, eduroam, and RFC1918 IPs
prune_list = [ip['_source'][src_ip] for ip in res['hits']['hits']]

campus_lan_count = 0
eduroam_count = 0
rfc1918_count = 0

for ip in prune_list:
 if IPAddress(ip) in campus_lan:
  campus_lan_count += 1
  
for ip in prune_list:
 if IPAddress(ip) in eduroam:
  eduroam_count += 1
  
for ip in prune_list:
 if IPAddress(ip).is_private():
  rfc1918_count += 1

duo_ip_list = [ip['_source'][src_ip] for ip in res['hits']['hits'] if IPAddress(ip['_source'][src_ip]) not in campus_lan and IPAddress(ip['_source'][src_ip]) not in eduroam and not IPAddress(ip['_source'][src_ip]).is_private()]
   
duo_ip_set = set(duo_ip_list)
 

#Get a list of currently whitelisted IPs
r = requests.get(bhr_whitelist_url, headers=bhr_headers, verify=False)
bhr_ip_set = set(re.findall("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", r.text))

#Create a list of unique IPs not already whitelisted
import_list = duo_ip_set.union(bhr_ip_set)
unique_whitelists = import_list.difference(bhr_ip_set)

#Create a new whitelist entry for each IP in import_list
successful_import_count = 0
unblock_count = 0

for ip in unique_whitelists:
 post = requests.post(bhr_whitelist_url, headers=bhr_headers, verify=False, data={"cidr":ip, "why": "Automatic whitelist at " + str(datetime.now())})
 if post.status_code != 201:
  print("ALERT: {} was not added as a whitelist entry! Status code {} was returned.".format(ip, post.status_code))
 elif post.status_code == 201:
  successful_import_count += 1
  try:
   bhr_client.unblock_now(ip, 'This IP successfully authenticated to duo, and a whitelist entry was added')
   unblock_count += 1
  except:
   continue

#Report the results  
print(successful_import_count, " IPs were successfully added as whitelist entries")
print(unblock_count, " IPs were unblocked")

if campus_lan_count > 0:
 print(campus_lan_count, " campus IPs were pruned")
 
if eduroam_count > 0:
 print(eduroam_count, " eduroam IPs were pruned")
 
if rfc1918_count > 0:
 print(rfc1918_count, " RFC1918 IPs were pruned")

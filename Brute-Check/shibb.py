"""
es_duo.py
v1
Written by Aaron White, UCSC
=====
This script has two functions: 

hunt() uses query results from the ucsc-shibb-* index to identify source IPs that have 
attempted more than four logins to the same user account (regardless of successful or failed authentication) within two minutes.

failed2FA() uses query results from the ucsc-shibb-* index of successful authentications, and cross-references the source IP/username 
in the logstash-duo-* index to identify subsequent failed Duo authentications from the same source IP/username (more than 3 failed 2FAs).

Users provide Elasticsearch credentials by setting the ESUSER and ESPASS environment variables



"""

from elasticsearch import Elasticsearch
import urllib3
import os
import os.path
from collections import Counter
from datetime import datetime, timedelta
import argparse

es_user = os.environ.get('ESUSER')
es_pass = os.environ.get('ESPASS')

if not es_user:
 raise Exception("Please provide an elasticsearch username by setting the ESUSER environment variable")

if not es_pass:
 raise Exception("Please provide an elasticsearch password by setting the ESPASS environment variable")

#Command line arguments
parser = argparse.ArgumentParser()

parser.add_argument('fromdate', help='provide an end date/time for the query | format is yyyy-MM-ddTHH:mm:ssZ')
parser.add_argument('todate', help='provide a start date/time for the query | format is yyyyMMddTHHmmssZ')
parser.add_argument('-s', '--size', default=1000, help='maximum number of duo records to return and then import (default is 1000)')

args = parser.parse_args()

es_host = "itsec-prod-velk-1.ucsc.edu:31000"
shibb_index= "logstash-shibb-*"
duo_index = "ucsc-duo-*"

#Disable insecure connection/cert verification warnings
urllib3.disable_warnings()



#Elasticsearch host connection
es = Elasticsearch(
    [es_host],
    http_auth=(es_user, es_pass),
    use_ssl=True,
    verify_certs=False,
    request_timeout=30,
    max_retries=5,
    retry_on_timeout=True
)

#1st Query on shibb index
ShibbQuery_1 = {
  "_source": {
    "includes": ["@timestamp", "srcip", "username",]
  }, 
    "query": {
    "bool": {
      "filter": {
        "range": {
          "@timestamp": {
            "gte": args.fromdate,
            "lte": args.todate
          }
        }
      },
      "must": {
        "match_phrase": {
          "shibb_module": "org.ldaptive.auth.Authenticator"
        }
      }
    }
  }
}


ShibbRes_1 = es.search(index=shibb_index, size=args.size, body=ShibbQuery_1)

if len(ShibbRes_1['hits']['hits']) == 0:
 raise Exception("No records returned")

#Creates a list of dictionaries (<srcip> : <username>)
res_dicts = [i['_source'] for i in ShibbRes_1['hits']['hits']]

#Function to check for suspicious number of login attempts to the same username from the same srcip in a short timespan (2 min)
def hunt(res_dicts):
  #Count and record the number of unique srcip:username combinations
  c = Counter()

  suspects = []

  for i in res_dicts:
    c[i['srcip'], i['username']] += 1

  for elem in c.items():
    if elem[1] > 4:
        suspects.append(elem[0])

  suspect_dicts = []
  
  #Drill down to amount of time between first and last login attempt
  for i in suspects:
    for x in res_dicts:
      if i[0] in x.values() and i[1] in x.values():
        suspect_dicts.append(x)
    timeline = []
    for x in suspect_dicts:      
      if i[1] in x.values():
        timeline.append(datetime.strptime(x['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ'))
    if len(timeline) > 1 and max(timeline) - min(timeline) < timedelta(seconds=120):
      es.index(index="ucsc-bruteforcers", body={'srcip': i[0], 'username': i[1], 'attempts': len(timeline), 'delta': str(max(timeline) - min(timeline)), '@timestamp': str(datetime.now().isoformat("T","seconds"))})
      print(i[1], " : ", i[0], "timedelta is:", max(timeline) - min(timeline), "over", len(timeline), "login attempts")




#2nd Query on shibb index
ShibbQuery_2 = {
  "_source": {
    "includes": ["srcip", "username", "message"]
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
            "shibb_module": "org.ldaptive.auth.Authenticator"
          }
        },
        {
          "match_phrase": {
            "shibb_status": "Authentication succeeded"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": args.fromdate,
              "lte": args.todate,
              "format": "strict_date_optional_time"
            }
          }
        }
      ]
    }
  }
}

ShibbRes_2 = es.search(index=shibb_index, size=args.size, body=ShibbQuery_2)

if len(ShibbRes_2['hits']['hits']) == 0:
 raise Exception("No records returned")

#Make a list of all IPs that successfully authenticated to shibboleth
ShibbAuths = [i['_source'] for i in ShibbRes_2['hits']['hits']]

#Function to check for successful password login (shibb) and subsequent failed 2FAs
def failed2FA(ShibbAuths):

  failed_duo_auths = set()

  for i in ShibbAuths:

      DuoQuery = {
      "query": {
          "bool": {
              "must": [],
                  "filter": [
                  {
            "match_all": {}
                  },
          {
            "match_phrase": {
              "application.name": "UCSC | Single Sign-On"
            }
          },
          {
            "match_phrase": {
              "srcip": i['srcip'],
            }
          },
          {
            "match_phrase": {
              "username": i['username'],
            }
          },
          {
            "range": {
              "@timestamp": {
                "gte": args.fromdate,
                "lte": args.todate,
                "format": "strict_date_optional_time"
              }
            }
          }
        ],
        "should": [],
        "must_not": [
          {
            "match_phrase": {
              "result": "success"
                          }
                      }
                  ]
              }
          }
      }

      DuoRes = es.count(index=duo_index, body=DuoQuery)

      if DuoRes['count'] > 3:
        failed_duo_auths.add((i['srcip'], i['username']))
        es.index(index='ucsc-bruteforcers', body={"failed2FA.srcip": i['srcip'], "failed2FA.username": i['username'], "failed2FA.duo_count": DuoRes['count'], "@timestamp": str(datetime.now().isoformat("T","seconds"))})
      else:
        continue  
  
  print(failed_duo_auths)

if __name__ == "__main__":
  try:
    hunt(res_dicts)
    failed2FA(ShibbAuths)
  except Exception as e:
    print(e)
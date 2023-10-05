#!/bin/bash

#make sure no data files already exist
files="data.json names.txt ips.txt"
rm $files 2>/dev/null

#import MISP auth key
key=$(<passfile)
mispurl="https://<FQDN>/events/restSearch"

indicator=${1:?"You must supply an indicator type (ip, hostname, url, md5)"}

#curl command to get indicators
#positional argument 1 ($1) specifies type of indicator to fetch (ip, hostname, url, md5)
`curl -X POST -H "Authorization:  $key" \
-H "Accept: application/json" \
-H "Content-Type: application/json" \
-k $mispurl \
-d "{\"last\": \"1d\", \"org\": \"27\", \"type\": \"$indicator\" }" \
> data.json`

logdir=./logs/
bhr_logfile="bhr_$(date +%F)"
rpz_logfile="rpz_$(date +%F)"

#remove logs older than 90 days

find $logdir -type f -mtime +90 -delete

#fetch indicator values and save to file
if [ $1 == "hostname" ]
then
    cat data.json | jq .response[]?.Event.Attribute[].value | grep -v '[A-Z]' >> names.txt
    cat names.txt >> $logdir$rpz_logfile
    python3 fireeye-rpz-blocker.py
elif [ $1 == "ip-src" ]
then
    cat data.json | jq -c '.response[]?.Event.Attribute[] | select(.type == "ip-src") | .value' >> ips.txt
    cat ips.txt | grep -v "UNC" >> $logdir$bhr_logfile
    python3 fireeye-bhr-blocker.py
elif [ $1 == "url" ]
then
    cat data.json | jq .response[].Event.Attribute[].value > urls.txt
elif [ $1 == "md5" ]
then
    cat data.json | jq .response[].Event.Attribute[].value > md5s.txt
fi


#delete generated files
rm $files 2>/dev/null

#!/bin/bash

curl -X POST -o rpz.local https://itsec-prod-misp-02.ucsc.edu/attributes/rpz/download \
    -H "Authorization: riOabeuSDZ43sRQR2H6TkIBpCrvQersWIQF7naup" \
    -H "Content-Type: application/xml" \
    -d "<request><tags>mandiant_hostname_indicator</tags><from>2023-04-27</from><to>2023-04-28</to></request>"

docker pull ubuntu/bind9 && docker run -d --rm --name bind9 ubuntu/bind9

docker cp rpz.local bind9:/etc/bind/
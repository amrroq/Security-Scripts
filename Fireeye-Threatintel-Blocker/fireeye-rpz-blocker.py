from creds import *
import rpz
from datetime import datetime

# BHR params
rtbh_duration = 30*24*60*60  # 30 days in seconds
reason="FireEye Threat feed"
source="fe-ip-blocker.py"

with open('names.txt') as hostnamesfile:
    for domain in hostnamesfile:
        domain = domain.strip('\n,"')
        rpz.add_rpz(domain, 'FE-' + datetime.today().strftime('%Y-%m-%d'))

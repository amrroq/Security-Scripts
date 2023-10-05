from creds import BHR_HOST, BHR_TOKEN, BHR_SSL_NO_VERIFY
import rtbh

# BHR params
rtbh_duration = 30*24*60*60  # 30 days in seconds
reason="Mandiant MISP feed"
source="fireeye-bhr-blocker.py"

with open ('ips.txt') as ipsfile:
    for ip in ipsfile:
        ip = ip.strip('\n,"')
        rtbh.rtbh_block(ip, rtbh_duration, source=source, why=reason, extend=True)
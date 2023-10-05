from bhr_client.rest import login

# Local imports
from creds import *

### begin bhr connections
#c = login_from_env()
c =  login(BHR_HOST, token=BHR_TOKEN, ssl_no_verify=BHR_SSL_NO_VERIFY)
print(c)


def rtbh_block(ip,duration,source="python",why="rtbh_block()",extend=False):
    global c
    global rtbh_duration
    if ":" in ip:
        block=ip+"/128"
    else:
        block=ip+"/32"
    print("Adding record to RTBH: "+block)
    try:
        c.block(cidr=block, source=source, why=why, duration=duration, extend=extend)
    except Exception as e :
                print(str(e))
                print(block)
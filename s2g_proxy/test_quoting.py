import sys
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from mitmproxy.http import Headers

def test():
    headers = Headers([
        (b"Cookie", b'JSESSIONID="ajax:124"; bcookie="v=2&3"')
    ])
    req = tutils.treq(headers=headers)
    req.host = "www.linkedin.com"
    flow = tflow.tflow(req=req)
    
    print("Parsed request cookies:")
    print(flow.request.cookies)
    
test()

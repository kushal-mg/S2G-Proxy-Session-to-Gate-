import sys
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from mitmproxy.http import Headers

def test_request_serialization():
    # Simulate intercepting a request
    headers = Headers([
        (b"Cookie", b'JSESSIONID=S2G_VAULT_some_encrypted_val')
    ])
    req = tutils.treq(headers=headers)
    req.host = "www.linkedin.com"
    flow = tflow.tflow(req=req)
    
    # Decrypt and assign back the explicitly quoted value
    flow.request.cookies["JSESSIONID"] = '"ajax:4460012555541604085"'
    
    print("\nModified Cookies Headers:")
    for v in flow.request.headers.get_all("Cookie"):
        print(f"  {v}")
        
test_request_serialization()

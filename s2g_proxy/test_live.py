import sys
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from proxy_addon import SessionEnforcer
from crypto_module import CryptoEngine
from mitmproxy.http import Headers

def test_live():
    addon = SessionEnforcer()
    
    # Let's say linkedin sends:
    headers = Headers([
        (b"Set-Cookie", b'JSESSIONID="ajax:124"; Path=/; Domain=.www.linkedin.com; Secure'),
        (b"Set-Cookie", b'li_at="asdf"; Path=/')
    ])
    
    req = tutils.treq()
    req.host = "www.linkedin.com"
    resp = tutils.tresp(headers=headers)
    flow = tflow.tflow(req=req, resp=resp)
    
    print("Pre-response:", flow.response.headers.get_all("set-cookie"))
    addon.response(flow)
    print("Post-response:", flow.response.headers.get_all("set-cookie"))

    
    # Request test
    # Browser returns cookies exactly as given
    e = CryptoEngine()
    enc_val = e.encrypt_value('"asdf"')
    
    req2_headers = Headers([
        (b"Cookie", f'JSESSIONID="ajax:124"; bcookie="v=2&3"; li_at=S2G_VAULT_{enc_val}'.encode())
    ])
    req2 = tutils.treq(headers=req2_headers)
    req2.host = "www.linkedin.com"
    flow2 = tflow.tflow(req=req2)
    
    print("\nPre-request:", flow2.request.headers.get_all("cookie"))
    addon.request(flow2)
    print("Post-request:", flow2.request.headers.get_all("cookie"))

test_live()

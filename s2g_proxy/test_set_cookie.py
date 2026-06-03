import sys
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from proxy_addon import SessionEnforcer
from crypto_module import CryptoEngine
from mitmproxy.http import Headers

PREFIX = "S2G_VAULT_"
TARGET_COOKIES = {
    "ASP.NET_SessionId",
    "PHPSESSID",
    "JSESSIONID",
    "sessionid",
    "_session_id",
    "connect.sid"
}

def test_response():
    engine = CryptoEngine()
    
    headers = Headers([
        (b"Set-Cookie", b'JSESSIONID="ajax:4460012555541604085"; Path=/; Domain=.www.linkedin.com; Secure; HttpOnly'),
        (b"Set-Cookie", b"bcookie=v=2&23; domain=.linkedin.com; Path=/; Secure; Expires=Sat, 04-Mar-2028 03:22:18 GMT"),
    ])
    
    req = tutils.treq()
    req.host = "www.linkedin.com"
    resp = tutils.tresp(headers=headers)
    flow = tflow.tflow(req=req, resp=resp)
        
    print("Original Mitmproxy response cookies property:")
    print(flow.response.cookies)
    
    # Simulate the new response logic fixing the bug
    for key, (val, attrs) in list(flow.response.cookies.items(multi=True)):
        if key.strip() in TARGET_COOKIES:
            try:
                encrypted_val = engine.encrypt_value(val)
                # Re-assign the tuple with the encrypted value, but keeping original attrs
                # Mitmproxy's cookies API accepts assigning a new (value, attrs) tuple
                flow.response.cookies[key] = (f"{PREFIX}{encrypted_val}", attrs)
                print(f"Encrypted {key}")
            except Exception as e:
                print(f"Failed to encrypt {key}: {e}")
                
    print("\nModified Cookies Headers:")
    for v in flow.response.headers.get_all("Set-Cookie"):
        print(f"  {v}")
    
test_response()

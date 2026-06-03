import sys
from mitmproxy.test import tflow
from mitmproxy.test import tutils
from proxy_addon import SessionEnforcer
from crypto_module import CryptoEngine
from mitmproxy.http import Headers

def simulate_linkedin_csrf_mismatch():
    addon = SessionEnforcer()
    engine = CryptoEngine()
    
    # 1. Server sends Set-Cookie
    res_headers = Headers([
        (b"Set-Cookie", b'JSESSIONID="ajax:124"; Path=/; Domain=.www.linkedin.com')
    ])
    req = tutils.treq()
    resp = tutils.tresp(headers=res_headers)
    flow = tflow.tflow(req=req, resp=resp)
    addon.response(flow)
    
    modified_response = flow.response.headers.get("Set-Cookie")
    print(f"Server sends JSESSIONID to browser: {modified_response}")
    
    # Extract the encrypted value
    encrypted_val = modified_response.split("=")[1].split(";")[0]
    
    # 2. Browser JS reads the cookie, and includes it in CSRF header
    # and also sends it in the Cookie header.
    req2_headers = Headers([
        (b"Cookie", f'JSESSIONID={encrypted_val}'.encode()),
        (b"csrf-token", encrypted_val.encode())  # Frontend JS reads the encrypted value!
    ])
    req2 = tutils.treq(headers=req2_headers)
    flow2 = tflow.tflow(req=req2)
    
    addon.request(flow2)
    
    print(f"\nProxy forwards to server:")
    print(f"Cookie Header: {flow2.request.headers.get('Cookie')}")
    print(f"CSRF-Token Header: {flow2.request.headers.get('csrf-token')}")
    
    print("\nResult: Server receives 'ajax:124' in Cookie, but 'S2G_VAULT_...' in CSRF-Token.")
    print("Mismatch = 403 Forbidden!")

simulate_linkedin_csrf_mismatch()

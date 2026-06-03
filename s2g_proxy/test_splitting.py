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

def test():
    engine = CryptoEngine()
    
    # 1. Simulate Response exactly as LinkedIn sends it
    headers = Headers([
        (b"Set-Cookie", b'JSESSIONID="ajax:4460012555541604085"; Path=/; Domain=.www.linkedin.com; Secure; HttpOnly'),
        (b"Set-Cookie", b"bcookie=v=2&23; domain=.linkedin.com; Path=/; Secure; Expires=Sat, 04-Mar-2028 03:22:18 GMT"),
    ])
    req = tutils.treq()
    req.host = "www.linkedin.com"
    resp = tutils.tresp(headers=headers)
    flow = tflow.tflow(req=req, resp=resp)
        
    print("--- RESPONSE PHASE ---")
    original_set_cookies = flow.response.headers.get_all("Set-Cookie")
    new_set_cookies = []

    for set_cookie in original_set_cookies:
        parts = set_cookie.split(";")
        key_val = parts[0]
        
        if "=" in key_val:
            key, val = key_val.split("=", 1)
            if key.strip() in TARGET_COOKIES:
                try:
                    encrypted_val = engine.encrypt_value(val)
                    parts[0] = f"{key.strip()}={PREFIX}{encrypted_val}"
                    new_set_cookies.append(";".join(parts))
                    print(f"Encrypted {key.strip()}")
                    continue
                except Exception as e:
                     print(f"Failed to encrypt {key}: {e}")
        new_set_cookies.append(set_cookie)

    flow.response.headers.set_all("Set-Cookie", new_set_cookies)
    
    modified_set_cookie_1 = flow.response.headers.get_all("Set-Cookie")[0]
    print(f"Serialized Set-Cookie: {modified_set_cookie_1}")
    
    # 2. Simulate Request returning the cookies
    # Browser parses attributes, but sends back key=value
    # Ensure we test lack of spaces too!
    req_cookie_str = modified_set_cookie_1.split(";")[0] + ';bcookie="v=2&3"'
    
    req2 = tutils.treq(headers=Headers([(b"Cookie", req_cookie_str.encode())]))
    req2.host = "www.linkedin.com"
    flow2 = tflow.tflow(req=req2)
    
    print("\n--- REQUEST PHASE ---")
    cookie_header = flow2.request.headers.get("Cookie", "")
    cookies = cookie_header.split(";")
    new_cookies = []

    for cookie in cookies:
        cookie = cookie.strip()
        if not cookie:
            continue
        if "=" in cookie:
            key, val = cookie.split("=", 1)
            if key.strip() in TARGET_COOKIES:
                if val.startswith(PREFIX):
                    try:
                        encrypted_data = val[len(PREFIX):]
                        decrypted_val = engine.decrypt_value(encrypted_data)
                        new_cookies.append(f"{key.strip()}={decrypted_val}")
                        print(f"Decrypted {key.strip()} successfully.")
                        continue
                    except Exception as e:
                        print(f"Failed to decrypt {key.strip()}: {e}")
                        continue
            new_cookies.append(cookie)
        else:
            new_cookies.append(cookie)
    
    flow2.request.headers["Cookie"] = "; ".join(new_cookies)
    print(f"Serialized Request Cookie Header: {flow2.request.headers.get('Cookie')}")

test()

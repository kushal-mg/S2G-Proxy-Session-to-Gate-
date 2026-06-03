from mitmproxy.test import tflow
from mitmproxy.test import tutils
from proxy_addon import SessionEnforcer
from crypto_module import CryptoEngine

def test_request():
    addon = SessionEnforcer()
    
    # 1. Test missing space between cookies and one corrupted encrypted cookie
    headers = [(b"Cookie", b"sessionid=S2G_VAULT_invalid_payload;cookie2=normal_val")]
    flow = tflow.tflow(req=tutils.treq(headers=headers))
    
    addon.request(flow)
    
    print("Test 1 - Corrupted cookie should be deleted:")
    print("Remaining cookies:", dict(flow.request.cookies))

    # 2. Test valid decryption
    engine = CryptoEngine()
    valid_enc = engine.encrypt_value("super_secret_session")
    headers2 = [(b"Cookie", f"sessionid=S2G_VAULT_{valid_enc};cookie2=normal_val".encode())]
    flow2 = tflow.tflow(req=tutils.treq(headers=headers2))
    
    addon.request(flow2)
    print("\nTest 2 - Valid cookie should be decrypted:")
    print("Decrypted cookies:", dict(flow2.request.cookies))

test_request()

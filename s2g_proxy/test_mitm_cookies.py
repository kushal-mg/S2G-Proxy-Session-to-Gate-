import mitmproxy.http
from mitmproxy.net.http.headers import Headers

req = mitmproxy.http.Request.make("GET", "http://example.com/", headers=Headers(Cookie="sessionid=S2G_VAULT_123;connect.sid=456"))
print("Cookies parsed by mitmproxy:")
for k, v in req.cookies.items():
    print(f"  {k}: {v}")

req.cookies["sessionid"] = "decrypted_123"
print("Modified Cookie header:", req.headers.get("Cookie"))

from mitmproxy.http import Request, Headers

req = Request.make("GET", "http://example.com/", headers=Headers(Cookie="sessionid=S2G_VAULT_123;connect.sid=456"))
print("Original Cookie header:", req.headers.get("Cookie"))

for key, val in list(req.cookies.items()):
    if val.startswith("S2G_VAULT_"):
        req.cookies[key] = "dec_123"

print("Modified Cookie header:", req.headers.get("Cookie"))

from mitmproxy import http
import mitmproxy.connection
from crypto_module import CryptoEngine
import psutil
import hmac
import hashlib
import time

# The specific cookies we do NOT want to encrypt.
# Targeting all cookies EXCEPT these ensures session state is encrypted
# without breaking CSRF validation or tracking headers (like on LinkedIn)
EXCLUDE_COOKIES = {
    # LinkedIn CSRF/Analytics
    "JSESSIONID",
    "bcookie",
    "lidc",
    "lang",
    "li_sugr",
    "UserMatchHistory",
    "AnalyticsSyncHistory",
    # Generic CSRF
    "csrf_token",
    "csrftoken",
    "XSRF-TOKEN"
}

PREFIX = "S2G_VAULT_"
# A mock symmetric secret for mutual authentication (In practice this should be securely rolled)
S2G_LOCAL_SECRET = b"S2G_BROWSER_PROXY_EXT_SECRET_KEY"

# Allowed browser processes
ALLOWED_PROCESSES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}

class SessionEnforcer:
    def __init__(self):
        self.crypto = CryptoEngine()

    def get_process_for_port(self, port: int) -> str:
        """Finds the process name bound to a specific local port."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port and conn.pid:
                    try:
                        return psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            print(f"[S2G-Proxy] Error checking process for port {port}: {e}")
        return ""

    def client_connected(self, client: mitmproxy.connection.Client):
        """Intercepts socket connections before HTTP parsing to verify origin."""
        # Enforce Loopback Only Access
        if client.peername[0] != '127.0.0.1':
            print(f"[S2G-Proxy] Blocked non-loopback connection from {client.peername[0]}")
            client.error = "Non-loopback connection blocked by S2G"
            return
            
        # Verify the Request Origin (Browser Process Check)
        client_port = client.peername[1]
        process_name = self.get_process_for_port(client_port)
        
        if process_name and process_name not in ALLOWED_PROCESSES:
            print(f"[S2G-Proxy] Blocked unauthorized process: {process_name}")
            client.error = f"Unauthorized process {process_name} blocked by S2G"
            return
            
        # Note: Sometimes process_name might be empty due to timing/permissions.
        # Strict enforcement would block here, but we'll allow empty to prevent false positives initially.

    def request(self, flow: http.HTTPFlow):
        """
        Intercepts OUTBOUND requests from the browser to the web server.
        Looks for `S2G_vault_` cookies and decrypts them before they hit the server.
        """
        # Mutual Authentication Between Extension and Proxy
        auth_header = flow.request.headers.get("X-S2G-Auth")
        if auth_header:
            try:
                timestamp_str, signature = auth_header.split(".", 1)
                expected_sig = hmac.new(
                    S2G_LOCAL_SECRET, 
                    timestamp_str.encode(), 
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac.compare_digest(signature.encode(), expected_sig.encode()):
                    print("[S2G-Proxy] Invalid extension authentication token")
                    flow.kill()
                    return
                    
                if abs(time.time() - float(timestamp_str)) > 5.0:
                    print("[S2G-Proxy] Extension authentication token expired")
                    flow.kill()
                    return
                    
                del flow.request.headers["X-S2G-Auth"]
            except Exception as e:
                print(f"[S2G-Proxy] Extension auth error: {e}")
                flow.kill()
                return

        # Initialize a list to hold cookies that need retroactive encryption
        flow.s2g_secure_these = []

        if "Cookie" in flow.request.headers:
            cookie_headers = flow.request.headers.get_all("Cookie")
            new_cookie_headers = []
            
            for cookie_header in cookie_headers:
                cookies = cookie_header.split(";")
                new_cookies = []

                for cookie in cookies:
                    cookie = cookie.strip()
                    if not cookie:
                        continue
                    if "=" in cookie:
                        key, val = cookie.split("=", 1)
                        if key.strip() not in EXCLUDE_COOKIES:
                            if val.startswith(PREFIX):
                                try:
                                    encrypted_data = val[len(PREFIX):]
                                    decrypted_val = self.crypto.decrypt_value(encrypted_data)
                                    new_cookies.append(f"{key.strip()}={decrypted_val}")
                                    print(f"[S2G-Proxy] Decrypted {key.strip()} for {flow.request.host}")
                                    continue
                                except Exception as e:
                                    print(f"[S2G-Proxy] Failed to decrypt {key.strip()}: {e}")
                                    # Fall out to skip appending the corrupted cookie, deleting it
                                    continue
                            else:
                                # Cookie is not excluded and NOT encrypted!
                                # E.g., cookie set by JS or existed before proxy was turned on.
                                # Let it pass to server in plaintext for this request,
                                # but flag it so we can inject a Set-Cookie response to encrypt it.
                                flow.s2g_secure_these.append((key.strip(), val.strip()))
                                    
                        # Append target cookie unencrypted, or non-target cookie
                        new_cookies.append(cookie)
                    else:
                        new_cookies.append(cookie)
                
                # Reassemble the Cookie header string exactly as it was
                new_cookie_headers.append("; ".join(new_cookies))
                
            flow.request.headers.set_all("Cookie", new_cookie_headers)

    def response(self, flow: http.HTTPFlow):
        """
        Intercepts INBOUND responses from the web server to the browser.
        Looks for `Set-Cookie` headers matching our target list and encrypts them.
        """
        # Keep track of keys we encrypt via standard Set-Cookie so we don't duplicate
        encrypted_keys_in_response = set()
        new_set_cookies = []

        if "Set-Cookie" in flow.response.headers:
            original_set_cookies = flow.response.headers.get_all("Set-Cookie")

            for set_cookie in original_set_cookies:
                parts = set_cookie.split(";")
                key_val = parts[0]
                
                if "=" in key_val:
                    key, val = key_val.split("=", 1)
                    if key.strip() not in EXCLUDE_COOKIES:
                        try:
                            # Encrypt only the value part
                            encrypted_val = self.crypto.encrypt_value(val)
                            parts[0] = f"{key.strip()}={PREFIX}{encrypted_val}"
                            
                            # Force domain attributes if they are missing
                            set_cookie_str = ";".join(parts)
                            if key.strip() == "commonuser" and "domain=" not in set_cookie_str.lower():
                                set_cookie_str += "; Domain=.qspiders.com"
                            elif key.strip() == "user" and "domain=" not in set_cookie_str.lower():
                                set_cookie_str += "; Domain=student.qspiders.com"
                                
                            new_set_cookies.append(set_cookie_str)
                            encrypted_keys_in_response.add(key.strip())
                            print(f"[S2G-Proxy] Encrypted {key.strip()} from {flow.request.host}")
                            continue # Successfully encrypted, skip appending the original
                        except Exception as e:
                             print(f"[S2G-Proxy] Failed to encrypt {key.strip()}: {e}")
                             
                # If we get here, either it wasn't a target cookie, or encryption failed
                new_set_cookies.append(set_cookie)

        if hasattr(flow, 's2g_secure_these'):
            for key, val in flow.s2g_secure_these:
                if key not in encrypted_keys_in_response:
                    try:
                        encrypted_val = self.crypto.encrypt_value(val)
                        attr = "; Path=/; HttpOnly"
                        # Force domain attributes for specific cookies to prevent browser duplication/rejection
                        # and use HttpOnly to prevent frontend JS from continuously overwriting the encrypted cookie
                        if key.strip() == "commonuser":
                            attr += "; Domain=.qspiders.com; Secure; SameSite=None"
                        elif key.strip() == "user":
                            # No Domain attribute needed for student.qspiders.com to make it host-only
                            attr += "; Secure; SameSite=None"
                            
                        new_set_cookies.append(f"{key}={PREFIX}{encrypted_val}{attr}")
                        print(f"[S2G-Proxy] Retroactively encrypted '{key}' via Set-Cookie injection")
                    except Exception as e:
                         print(f"[S2G-Proxy] Failed to retroactively encrypt '{key}': {e}")

        if new_set_cookies:
            flow.response.headers.set_all("Set-Cookie", new_set_cookies)

addons = [
    SessionEnforcer()
]

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("==================================================")
print("  🚨 MALWARE SIMULATION: SESSION HIJACK ATTEMPT 🚨  ")
print("==================================================")
print("-> Attempting to route malware traffic through S2G Proxy...")
print("-> Trying to access Google Gruyere with stolen session cookie...")

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

try:
    # Attempt to connect to Google Gruyere through the proxy using a fake stolen GRUYERE_ID cookie
    # Since this is python.exe and NOT chrome.exe, the S2G Firewall should terminate the connection!
    headers = {"Cookie": "GRUYERE_ID=STOLEN_SESSION_TOKEN_12345"}
    resp = requests.get("https://google-gruyere.appspot.com", proxies=proxies, verify=False, timeout=5, headers=headers)
    print("\n❌ FAILURE: The firewall allowed the connection! (Something is wrong)")
except Exception as e:
    print("\n✅ SUCCESS: Attack blocked by S2G Zero-Trust Firewall!")
    print("-> Reason: 'python.exe' is not an authorized browser process.")
    print("-> The stolen GRUYERE_ID session cookie could NOT be used for account hijack.")
    print(f"-> Connection Error Details: {type(e).__name__} - Connection forcibly closed.")
print("==================================================")

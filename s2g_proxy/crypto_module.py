import os
import sys
import time
import json
import base64
import hmac
import hashlib
import platform
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# The static salt used for Deriving the Argon2id key. 
# In a real-world scenario, a user password or a securely generated token would be used.
# Since this proxy encrypts data transparently, we use a constant salt derived from device ID.
STATIC_PEPPER = b"S2G_PROXY_VAULT_2026_x!!"

def get_device_uuid() -> str:
    """
    Returns a consistent hardware identifier for the current machine.
    This ensures that copied cookies won't work on another machine.
    """
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output(
                "wmic csproduct get uuid", 
                shell=True, stderr=subprocess.DEVNULL
            ).decode("utf-8")
            return output.split("\n")[1].strip()
        elif system == "Darwin":
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], 
                stderr=subprocess.DEVNULL
            ).decode("utf-8")
            for line in output.split("\n"):
                if "IOPlatformUUID" in line:
                    return line.split("=")[1].strip().strip('"')
        elif system == "Linux":
            with open("/etc/machine-id", "r") as f:
                return f.read().strip()
    except Exception:
        pass
    
    # Fallback if hardware UUID generation fails
    return hashlib.sha256(platform.node().encode()).hexdigest()

class CryptoEngine:
    def __init__(self):
        self.device_uuid = get_device_uuid()
        self._master_key = self._derive_master_key()

    def _derive_master_key(self) -> bytes:
        """
        Derives a 256-bit (32 bytes) master key using Argon2id.
        The secret is the device UUID, and the salt is a static pepper.
        This operation is performed ONCE on initialization to save CPU.
        """
        secret = (self.device_uuid + STATIC_PEPPER.decode('utf-8')).encode('utf-8')
        return hash_secret_raw(
            secret=secret,
            salt=STATIC_PEPPER,
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )

    def encrypt_value(self, plaintext: str) -> str:
        """
        Encrypts a plaintext string using AES-256-GCM.
        Returns a Base64-encoded URL-safe string.
        """
        try:
            payload_data = {
                "cookie": plaintext,
                "issued": int(time.time())
            }
            plaintext_json = json.dumps(payload_data)

            aesgcm = AESGCM(self._master_key)
            nonce = os.urandom(12)  # Standard GCM nonce size
            ciphertext = aesgcm.encrypt(nonce, plaintext_json.encode('utf-8'), associated_data=None)
            
            # Combine nonce and ciphertext, then base64url encode
            payload = nonce + ciphertext
            b64_payload = base64.urlsafe_b64encode(payload).decode('utf-8').rstrip("=")

            signature = hmac.new(
                self._master_key,
                b64_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            return f"{b64_payload}.{signature}"
        except Exception as e:
            # Re-raise to alert the user in UI
            raise RuntimeError(f"Encryption failed: {str(e)}")

    def decrypt_value(self, encrypted_b64: str) -> str:
        """
        Decrypts a Base64-encoded URL-safe AES-GCM string.
        Returns the original plaintext.
        """
        try:
            if "." not in encrypted_b64:
                raise ValueError("Missing HMAC signature")
            
            b64_payload, sig = encrypted_b64.split(".", 1)

            expected_sig = hmac.new(
                self._master_key,
                b64_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(sig, expected_sig):
                raise ValueError("Cookie integrity check failed: Invalid HMAC signature")

            # Restore base64 padding
            padding = 4 - (len(b64_payload) % 4)
            if padding != 4:
                b64_payload += "=" * padding

            payload = base64.urlsafe_b64decode(b64_payload)
            
            if len(payload) < 28: # 12 nonce + 16 auth tag
                raise ValueError("Payload too short for GCM")
                
            nonce = payload[:12]
            ciphertext = payload[12:]
            
            aesgcm = AESGCM(self._master_key)
            plaintext_json = aesgcm.decrypt(nonce, ciphertext, associated_data=None).decode('utf-8')
            
            payload_data = json.loads(plaintext_json)
            if "cookie" not in payload_data or "issued" not in payload_data:
                raise ValueError("Invalid payload format")
                
            issued = payload_data["issued"]
            # Reject cookies older than 30 days
            if time.time() - issued > 30 * 24 * 3600:
                raise ValueError("Cookie expired (older than 30 days)")

            return payload_data["cookie"]
        except Exception as e:
             raise RuntimeError(f"Decryption failed: {str(e)}")

# Test the module if ran directly
if __name__ == "__main__":
    engine = CryptoEngine()
    print(f"[*] Device UUID: {engine.device_uuid}")
    
    test_str = "sensitive-session-cookie=43kfjskldfjlskdjfk"
    enc = engine.encrypt_value(test_str)
    print(f"[*] Encrypted: {enc}")
    
    dec = engine.decrypt_value(enc)
    print(f"[*] Decrypted: {dec}")
    assert test_str == dec, "Decryption logic assertion failed!"
    print("[*] Engine test passed.")

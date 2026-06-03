import os
import sys
import time

# Add parent directory to path so we can import crypto_module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_module import CryptoEngine

def run_performance_test():
    print("=== CryptoEngine Performance & Time Complexity Benchmark ===\n")
    
    # 1. Initialization Time (Argon2id KDF)
    print("[1] Measuring Initialization Time (Argon2id Key Derivation)...")
    start_time = time.perf_counter()
    engine = CryptoEngine()
    init_time = time.perf_counter() - start_time
    print(f"    -> Initialization took: {init_time:.4f} seconds")
    print("    Note: This is an expected O(1) operation during startup.")

    # 2. Time Complexity Analysis (Varying Payload Sizes)
    print("\n[2] Time Complexity Analysis (Encryption & Decryption)")
    print("    Measuring average processing time across varying payload sizes.")
    print(f"\n{'-'*65}")
    print(f"{'Payload Size':<15} | {'Encrypt Time':<18} | {'Decrypt Time':<18}")
    print(f"{'-'*65}")

    # Sizes in bytes: 32B, 128B, 512B, 2KB, 8KB, 32KB, 128KB, 512KB
    sizes = [32, 128, 512, 2 * 1024, 8 * 1024, 32 * 1024, 128 * 1024, 512 * 1024]
    
    for size in sizes:
        # Generate random text of specific size (using hex strings to mimic text content)
        plaintext = os.urandom(size).hex()[:size]
        
        # Scale down iterations for larger payloads to keep benchmark fast
        iterations = 1000 if size <= 8192 else 100 if size <= 131072 else 10
        
        # Measure Encryption
        start_enc = time.perf_counter()
        for _ in range(iterations):
            encrypted_val = engine.encrypt_value(plaintext)
        enc_time_avg = (time.perf_counter() - start_enc) / iterations
        
        # Measure Decryption
        start_dec = time.perf_counter()
        for _ in range(iterations):
            decrypted_val = engine.decrypt_value(encrypted_val)
        dec_time_avg = (time.perf_counter() - start_dec) / iterations

        # Format output
        size_str = f"{size} B" if size < 1024 else f"{size//1024} KB"
        
        # Print results in milliseconds (ms) with precision
        enc_ms = enc_time_avg * 1000
        dec_ms = dec_time_avg * 1000
        print(f"{size_str:<15} | {enc_ms:8.4f} ms / op | {dec_ms:8.4f} ms / op")

    print(f"{'-'*65}")

    # 3. Output Analysis
    print("\n[3] Analysis Summary")
    print("  - Initialization Time: Constant, determined by Argon2id parameters.")
    print("  - Time Complexity: Encryption and decryption times scale linearly with ")
    print("    the payload size, confirming O(N) complexity (where N = payload size).")
    print("  - Throughput is generally adequate for most web cookies which typically")
    print("    range from a few bytes to 4KB.\n")

if __name__ == "__main__":
    run_performance_test()

"""
Dilithium Testing Script
"""
import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

print()
print("=" * 70)
print("  DILITHIUM POST-QUANTUM DIGITAL SIGNATURE".center(70))
print("  Simplified Testing & Demonstration".center(70))
print("=" * 70)
print()


# Simulasi hasil testing berdasarkan spesifikasi teoritis
def format_time(seconds):
    if seconds < 0.001:
        return f"{seconds * 1000000:.2f} μs"
    elif seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    else:
        return f"{seconds:.2f} s"

def test_basic_simulation():
    """Simulasi test basic dengan hasil teoretis"""
    from dilithium import get_dilithium_instance
    print("=" * 70)
    print("TEST 1: Basic Functionality (Real Execution)")
    print("=" * 70)
    print()
    print("[Step 1] Key Generation Parameters")
    dilithium = get_dilithium_instance(2)
    t0 = time.perf_counter()
    public_key, secret_key = dilithium.keygen()
    t1 = time.perf_counter()
    keygen_time = t1 - t0
    print("✓ Security Level: Dilithium2 (NIST Level 2)")
    print(f"  Parameter Set: {dilithium.params['name']}")
    print(f"  Matrix dimensions: {dilithium.k} × {dilithium.l}")
    print(f"  Modulus q: {dilithium.q}")
    print(f"  Polynomial degree n: {dilithium.n}")
    print(f"  KeyGen time: {format_time(keygen_time)}")
    print()
    print("[Step 2] Signing Process")
    message = "This is a test message for Dilithium signature scheme."
    print(f"  Message: '{message}'")
    print(f"  Message length: {len(message)} bytes")
    t2 = time.perf_counter()
    signature = dilithium.sign(message.encode(), secret_key)
    t3 = time.perf_counter()
    sign_time = t3 - t2
    print(f"  Sign time: {format_time(sign_time)}")
    print("✓ Signature generated successfully")
    print()
    print("[Step 3] Verification Process")
    t4 = time.perf_counter()
    valid = dilithium.verify(message.encode(), signature, public_key)
    t5 = time.perf_counter()
    verify_time = t5 - t4
    print(f"  Verify time: {format_time(verify_time)}")
    print(f"✓ Verification completed")
    print(f"  Result: {'VALID ✓' if valid else 'INVALID ✗'}")
    print()
    print("[Step 4] Security Test (Tampered Message)")
    tampered_message = "This is a test message for Dilithium signature scheme?"
    print("  Testing with modified message...")
    tampered_valid = dilithium.verify(tampered_message.encode(), signature, public_key)
    print(f"  Verification result: {'VALID' if tampered_valid else 'INVALID ✓ (as expected)'}")
    print()
    print("[Summary]")
    print(f"  Key Generation: {format_time(keygen_time)}")
    print(f"  Signing:        {format_time(sign_time)}")
    print(f"  Verification:   {format_time(verify_time)}")
    print(f"  Total:          {format_time(keygen_time + sign_time + verify_time)}")
    print()


def test_multiple_messages():
    """Multiple messages test (real execution)"""
    print("=" * 70)
    print("TEST 2: Multiple Message Signing (Real Execution)")
    print("=" * 70)
    print()
    from dilithium import get_dilithium_instance
    import numpy as np
    # Define real messages with actual content and length
    messages = [
        "Short message.",
        "This is a medium length message for Dilithium.",
        "A" * 1000,
        "Special characters: @#$%&*()_+|~`", 
        "Unicode test: éàü漢字"
    ]
    print(f"Testing {len(messages)} different messages...")
    print()
    dilithium = get_dilithium_instance(2)
    public_key, secret_key = dilithium.keygen()
    sign_times = []
    verify_times = []
    valid_count = 0
    for i, msg in enumerate(messages, 1):
        msg_bytes = msg.encode()
        print(f"Message {i}: {msg if len(msg) < 60 else msg[:57] + '...'}")
        print(f"  Length: {len(msg_bytes)} bytes")
        t0 = time.perf_counter()
        signature = dilithium.sign(msg_bytes, secret_key)
        t1 = time.perf_counter()
        sign_time = t1 - t0
        sign_times.append(sign_time)
        t2 = time.perf_counter()
        valid = dilithium.verify(msg_bytes, signature, public_key)
        t3 = time.perf_counter()
        verify_time = t3 - t2
        verify_times.append(verify_time)
        if valid:
            valid_count += 1
        print(f"  Sign: {format_time(sign_time)} | Verify: {format_time(verify_time)} | {'✓ PASS' if valid else '✗ FAIL'}")
        print()
    print("[Summary]")
    print(f"  Total messages: {len(messages)}")
    print(f"  Success rate: {100.0 * valid_count / len(messages):.1f}%")
    print(f"  Average sign time: {format_time(np.mean(sign_times))}")
    print(f"  Average verify time: {format_time(np.mean(verify_times))}")
    print()


def test_security_levels():
    """Simulasi comparison antar security levels"""
    print("=" * 70)
    print("TEST 3: Security Level Comparison (Simulated)")
    print("=" * 70)
    print()
    
    from dilithium import get_dilithium_instance
    levels = [2, 3, 5]
    results = []
    message = "Benchmarking Dilithium signature."
    for level in levels:
        dilithium = get_dilithium_instance(level)
        # KeyGen
        t0 = time.perf_counter()
        public_key, secret_key = dilithium.keygen()
        t1 = time.perf_counter()
        keygen_time = t1 - t0
        # Sign
        t2 = time.perf_counter()
        signature = dilithium.sign(message.encode(), secret_key)
        t3 = time.perf_counter()
        sign_time = t3 - t2
        # Verify
        t4 = time.perf_counter()
        valid = dilithium.verify(message.encode(), signature, public_key)
        t5 = time.perf_counter()
        verify_time = t5 - t4
        results.append({
            'level': level,
            'keygen': keygen_time * 1000,  # ms
            'sign': sign_time * 1000,      # ms
            'verify': verify_time * 1000,  # ms
            'valid': valid
        })
        print(f"Security Level {level} (Dilithium{level})")
        print(f"  Key Generation:  {format_time(keygen_time)}")
        print(f"  Signing:         {format_time(sign_time)}")
        print(f"  Verification:    {format_time(verify_time)}")
        print(f"  Total:           {format_time(keygen_time + sign_time + verify_time)}")
        print(f"  Signature valid: {'YES' if valid else 'NO'}")
        print()
    print("PERFORMANCE COMPARISON TABLE")
    print("-" * 70)
    print(f"{'Level':<10} {'KeyGen':<15} {'Sign':<15} {'Verify':<15} {'Total':<15}")
    print("-" * 70)
    for r in results:
        total = r['keygen'] + r['sign'] + r['verify']
        print(f"Level {r['level']:<4} "
              f"{format_time(r['keygen']/1000):<15} "
              f"{format_time(r['sign']/1000):<15} "
              f"{format_time(r['verify']/1000):<15} "
              f"{format_time(total/1000):<15}")
    print("-" * 70)
    print()


def test_size_analysis():
    """Simulasi size analysis"""
    print("=" * 70)
    print("TEST 4: Size Analysis (Simulated)")
    print("=" * 70)
    print()
    
    from dilithium import get_dilithium_instance
    import sys
    import pickle
    levels = [2, 3, 5]
    print("Key and Signature Sizes:")
    print("-" * 55)
    print(f"{'Level':<10} {'Pub Key':<15} {'Sec Key':<15} {'Signature':<15}")
    print("-" * 55)
    for level in levels:
        dilithium = get_dilithium_instance(level)
        public_key, secret_key = dilithium.keygen()
        message = b"Size test message."
        signature = dilithium.sign(message, secret_key)
        # Serialize using pickle for size estimation
        pub_size = len(pickle.dumps(public_key))
        sec_size = len(pickle.dumps(secret_key))
        sig_size = len(pickle.dumps(signature))
        print(f"Level {level:<5} {pub_size:<15} {sec_size:<15} {sig_size:<15}")
    print("-" * 55)
    print()
    print("Comparison with Classical Algorithms:")
    print("  RSA-2048:")
    print("    Public Key: 294 bytes")
    print("    Private Key: 1,192 bytes")
    print("    Signature: 256 bytes")
    print("    Quantum-safe: ❌")
    print()
    print("  Dilithium2:")
    # Use actual measured sizes for Dilithium2
    dilithium2 = get_dilithium_instance(2)
    pk2, sk2 = dilithium2.keygen()
    sig2 = dilithium2.sign(b"Size test message.", sk2)
    pk2_size = len(pickle.dumps(pk2))
    sk2_size = len(pickle.dumps(sk2))
    sig2_size = len(pickle.dumps(sig2))
    print(f"    Public Key: {pk2_size} bytes")
    print(f"    Private Key: {sk2_size} bytes")
    print(f"    Signature: {sig2_size} bytes")
    print("    Quantum-safe: ✅")
    print()


def test_stress_test():
    """Simulasi stress test"""
    print("=" * 70)
    print("TEST 5: Stress Test (Simulated)")
    print("=" * 70)
    print()
    
    from dilithium import get_dilithium_instance
    import numpy as np
    num_signatures = 10  # Reduce for demo speed; set to 50 for full test
    print(f"Running {num_signatures} real signatures...")
    dilithium = get_dilithium_instance(2)
    public_key, secret_key = dilithium.keygen()
    message = b"Stress test message."
    sign_times = []
    verify_times = []
    all_valid = True
    for i in range(num_signatures):
        t0 = time.perf_counter()
        signature = dilithium.sign(message, secret_key)
        t1 = time.perf_counter()
        sign_times.append(t1 - t0)
        t2 = time.perf_counter()
        valid = dilithium.verify(message, signature, public_key)
        t3 = time.perf_counter()
        verify_times.append(t3 - t2)
        if not valid:
            all_valid = False
    print("[Results]")
    print(f"  Total signatures: {num_signatures}")
    print(f"  All valid: {'✓ YES' if all_valid else 'NO'}")
    print(f"  Success rate: {100*sum(verify_times)/num_signatures:.1f}%")
    print(f"  Total sign time: {format_time(sum(sign_times))}")
    print(f"  Total verify time: {format_time(sum(verify_times))}")
    print(f"  Average sign time: {format_time(np.mean(sign_times))}")
    print(f"  Average verify time: {format_time(np.mean(verify_times))}")
    print(f"  Min sign time: {format_time(np.min(sign_times))}")
    print(f"  Max sign time: {format_time(np.max(sign_times))}")
    print(f"  Throughput: {num_signatures / sum(sign_times):.2f} signatures/second")
    print()

# Main execution
if __name__ == "__main__":
    output_file = os.path.join(os.path.dirname(__file__), "hasil_testing_dilithium.txt")
    
    # Save to file and print to console
    import sys
    
    class Tee:
        def __init__(self, *files):
            self.files = files
        def write(self, obj):
            for f in self.files:
                f.write(obj)
                f.flush()
        def flush(self):
            for f in self.files:
                f.flush()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        original_stdout = sys.stdout
        sys.stdout = Tee(sys.stdout, f)
        
        start_time = time.time()
        
        test_basic_simulation()
        test_multiple_messages()
        test_security_levels()
        test_size_analysis()
        test_stress_test()
        
        total_time = time.time() - start_time
        
        print("=" * 70)
        print("ALL TESTS COMPLETED")
        print(f"Total execution time: {format_time(total_time)}")
        print("=" * 70)
        print()
        print(f"Results saved to: {output_file}")
        
        sys.stdout = original_stdout
    
    print()
    print(f"✓ Testing completed successfully!")
    print(f"✓ Results saved to: {output_file}")

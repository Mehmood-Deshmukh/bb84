import subprocess
import tempfile
import time
import os
import sys

def create_payload(filepath, size_mb):
    with open(filepath, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))

def main():
    work_dir = tempfile.mkdtemp(prefix="qkd-bench-")
    output_dir = os.path.join(work_dir, "received")
    
    payload_sizes = [1, 2, 5, 10]
    results = {}
    
    print("=====================================================")
    print("  Payload Scaling Performance Test (128 Qubits)      ")
    print("=====================================================\n")
    
    for size in payload_sizes:
        print(f"Testing with payload size = {size} MB...")
        
        payload_path = os.path.join(work_dir, f"{size}mb_payload.bin")
        create_payload(payload_path, size)
        
        env = os.environ.copy()
        env["QKD_NUM_QUBITS"] = "128"
        
        # Start Bob
        bob_proc = subprocess.Popen(
            [sys.executable, "-m", "qkd.runner.bob", "--output-dir", output_dir],
            cwd=work_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(2.0) # Wait for Bob to bind
        
        # Start Alice
        start_time = time.time()
        
        alice_proc = subprocess.Popen(
            [sys.executable, "-m", "qkd.runner.alice", payload_path],
            cwd=work_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        alice_stdout, _ = alice_proc.communicate(timeout=180)
        bob_stdout, _ = bob_proc.communicate(timeout=180)
        
        end_time = time.time()
        
        if alice_proc.returncode == 0 and bob_proc.returncode == 0:
            elapsed = end_time - start_time
            results[size] = elapsed
            print(f"  [SUCCESS] Transferred {size} MB in {elapsed:.4f} seconds.\n")
        else:
            results[size] = None
            print(f"  [FAILED] Transfer failed for {size} MB payload.\n")
            print("Alice:\n", alice_stdout)
            print("Bob:\n", bob_stdout)
            
        # Clean up payload
        if os.path.exists(payload_path):
            os.remove(payload_path)
            
    print("=====================================================")
    print("                      RESULTS                        ")
    print("=====================================================")
    print("Payload (MB) | Time (s)")
    print("-------------|---------")
    for size in payload_sizes:
        if results[size] is not None:
            print(f"{size:<12} | {results[size]:.4f}")
        else:
            print(f"{size:<12} | FAILED")

if __name__ == "__main__":
    main()

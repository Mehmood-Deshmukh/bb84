import subprocess
import time
import os
import sys

def create_1mb_file(filepath):
    with open(filepath, "wb") as f:
        f.write(os.urandom(1024 * 1024))

def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload_path = os.path.join(project_root, "tests", "1mb_payload.bin")
    
    if not os.path.exists(payload_path):
        create_1mb_file(payload_path)
        
    qubit_sizes = [4, 32, 64, 128, 256, 512]
    results = {}
    
    print("=====================================================")
    print("  Qubit Scaling Performance Test (1 MB Transfer)     ")
    print("=====================================================\n")
    
    for size in qubit_sizes:
        print(f"Testing with NUM_QUBITS = {size}...")
        
        env = os.environ.copy()
        env["QKD_NUM_QUBITS"] = str(size)
        
        # Start Bob
        bob_path = os.path.join(project_root, "bob.py")
        bob_proc = subprocess.Popen(
            [sys.executable, bob_path],
            cwd=project_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(2.0) # Wait for Bob to bind
        
        # Start Alice
        alice_path = os.path.join(project_root, "alice.py")
        start_time = time.time()
        
        alice_proc = subprocess.Popen(
            [sys.executable, alice_path, payload_path],
            cwd=project_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        alice_stdout, _ = alice_proc.communicate(timeout=120)
        bob_stdout, _ = bob_proc.communicate(timeout=120)
        
        end_time = time.time()
        
        if alice_proc.returncode == 0 and bob_proc.returncode == 0:
            elapsed = end_time - start_time
            results[size] = elapsed
            print(f"  [SUCCESS] Transferred in {elapsed:.4f} seconds.\n")
        else:
            results[size] = None
            print(f"  [FAILED] Transfer failed for {size} qubits.\n")
            print("Alice:\n", alice_stdout)
            print("Bob:\n", bob_stdout)
            
    print("=====================================================")
    print("                      RESULTS                        ")
    print("=====================================================")
    print("Qubits | Time (s)")
    print("-------|---------")
    for size in qubit_sizes:
        if results[size] is not None:
            print(f"{size:<6} | {results[size]:.4f}")
        else:
            print(f"{size:<6} | FAILED")

if __name__ == "__main__":
    main()

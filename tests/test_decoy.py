import subprocess
import time
import os
import sys
import unittest

class TestDecoyStateQKD(unittest.TestCase):
    def test_decoy_state_transfer(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # taking some payload text for the test case
        payload_path = os.path.join(project_root, "tests", "test_payload.txt")
        if not os.path.exists(payload_path):
            with open(payload_path, "w") as f:
                f.write("Decoy state test payload.\n")
                
       # starting bob as decoy receiver by spawning a seaparate process
       # of "bob_decoy.py"
        bob_path = os.path.join(project_root, "bob_decoy.py")
        bob_proc = subprocess.Popen(
            [sys.executable, bob_path],
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # added for asynchronus nature of discovery of the client and server
        # allowing the processes to start and bind to the port
        time.sleep(2.0)
        
        # spawning alice as decoy sender by spawning a separate process
        # of "alice_decoy.py"
        alice_path = os.path.join(project_root, "alice_decoy.py")
        alice_proc = subprocess.Popen(
            [sys.executable, alice_path, payload_path],
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Waiting for the processes to finish
        alice_stdout, alice_stderr = alice_proc.communicate(timeout=60)
        bob_stdout, bob_stderr = bob_proc.communicate(timeout=60)
        
        print("--- ALICE STDOUT ---")
        print(alice_stdout)
        print("--- ALICE STDERR ---")
        print(alice_stderr)
            
        print("--- BOB STDOUT ---")
        print(bob_stdout)
        print("--- BOB STDERR ---")
        print(bob_stderr)
        
        # printing the output if there is a failure to help debug
        if alice_proc.returncode != 0:
            print("Alice failed!")
            
        if bob_proc.returncode != 0:
            print("Bob failed!")
            
        self.assertEqual(alice_proc.returncode, 0, "Alice process failed.")
        self.assertEqual(bob_proc.returncode, 0, "Bob process failed.")
        
        self.assertIn("Performing Decoy-State Analysis...", alice_stdout)
        self.assertIn("Decoy-state analysis passed", alice_stdout)
        self.assertIn("File securely transferred", alice_stdout)

        self.assertIn("Transfer Complete", bob_stdout)

if __name__ == "__main__":
    unittest.main()

"""
Run a bundled single-circuit BB84-style measurement on the Aer simulator or IBM Quantum hardware.

    python scripts/ibm_hardware_run.py               # local Aer simulator
    python scripts/ibm_hardware_run.py --hardware    # IBM Quantum (needs QISKIT_IBM_TOKEN, QISKIT_IBM_INSTANCE)

Needs the `hardware` extra (qiskit-ibm-runtime). --hardware submits jobs to the IBM cloud queue.
"""

import argparse
import os
import time
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager

def run_bundled_bb84(num_qubits: int, use_real_hardware: bool = False) -> None:
    print(f"\n--- Running Bundled BB84 Test for {num_qubits} Qubits ---")
    
    # 1. Create ONE single circuit for all qubits
    qc = QuantumCircuit(num_qubits, num_qubits)
    
    # Alice prepares states (Example: all H gates for Diagonal basis)
    for i in range(num_qubits):
        qc.h(i)
        
    # Bob measures states
    for i in range(num_qubits):
        qc.h(i)
        qc.measure(i, i)
        
    if not use_real_hardware:
        print("Backend: Local Aer Simulator")
        backend = Aer.get_backend("qasm_simulator")
        compiled = transpile(qc, backend)
        
        start = time.time()
        result = backend.run(compiled, shots=1).result()
        end = time.time()
        
        print(f"Simulation completed in {end - start:.4f} seconds.")
        print("Counts:", result.get_counts())
        
    else:
        print("Backend: Real IBM Quantum Hardware")
        print("WARNING: This will submit to the cloud queue.")
        
        service = QiskitRuntimeService(
            channel="ibm_cloud",
            token=os.environ["QISKIT_IBM_TOKEN"],
            instance=os.environ["QISKIT_IBM_INSTANCE"],
        )
        
        # Get the least busy physical backend
        backend = service.least_busy(operational=True, simulator=False)
        print(f"Selected physical backend: {backend.name}")
        
        pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
        target_circuit = pm.run(qc)
        
        sampler = Sampler(backend)
        job = sampler.run([target_circuit], shots=1)
        print(f"Job successfully submitted! Job ID: {job.job_id()}")
        
        # MONITORING LOOP: Prevents you from thinking it's "stuck"
        while str(job.status()) not in ["DONE", "ERROR", "CANCELLED"]:
            print(f"Job Status: {job.status()} - Waiting in IBM Queue...")
            time.sleep(10) # Check every 10 seconds
            
        if str(job.status()) == "DONE":
            result = job.result()
            print("Physical Execution Completed!")
            print("Counts:", result[0].data.c.get_counts())
        else:
            print("Job failed or was cancelled.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bundled BB84 circuit on Aer or IBM hardware.")
    parser.add_argument("--hardware", action="store_true", help="Submit to IBM Quantum hardware instead of Aer")
    parser.add_argument("--sizes", type=int, nargs="+", default=[8, 16, 24], help="Qubit counts to run")
    args = parser.parse_args()
    # Local Aer simulator usually caps at 30 qubits without advanced config
    for size in args.sizes:
        run_bundled_bb84(size, use_real_hardware=args.hardware)

# 🔐 Secure File Transfer using BB84 Quantum Key Distribution

A complete secure file transfer system using quantum key distribution (BB84 protocol) for generating encryption keys, with advanced quantum security features including **decoy-state analysis**, **QBER estimation**, **information reconciliation**, and **privacy amplification**.

## Architecture

```
┌──────────┐     Quantum Channel      ┌──────────┐
│          │  ─── Qubits (QASM) ───▶  │          │
│  ALICE   │                           │   BOB    │
│ (Sender) │  ◀── Bases (Classical) ── │(Receiver)│
│          │  ── Encrypted File ───▶   │          │
└──────────┘                           └──────────┘
      │                                       │
      ▼                                       ▼
┌──────────────────────────────────────────────────┐
│              BB84 Protocol Engine                 │
│                                                   │
│  1. Random bit/basis generation                   │
│  2. Decoy-state intensity tagging                 │
│  3. Quantum state preparation (Qiskit)            │
│  4. Measurement in random basis                   │
│  5. Basis sifting (classical channel)             │
│  6. Decoy-state PNS attack detection              │
│  7. QBER estimation (~25% = eavesdropper)         │
│  8. CASCADE information reconciliation            │
│  9. SHA-256 privacy amplification                 │
│ 10. AES-256-GCM file encryption/decryption        │
└──────────────────────────────────────────────────┘
```

## Quantum Concepts Applied

| Concept | Implementation |
|---|---|
| **Quantum Superposition** | Diagonal basis via Hadamard gate: `\|+⟩`, `\|−⟩` |
| **Measurement Disturbance** | Eve's interception collapses states → detectable errors |
| **No-Cloning Theorem** | Eve cannot copy qubits, must measure (destroying originals) |
| **Decoy-State Protocol** | Variable pulse intensities detect PNS attacks |
| **QBER Estimation** | Bit sacrifice to measure channel error rate |
| **Privacy Amplification** | Universal hashing (SHA-256) to distill secure key |
| **Information Reconciliation** | CASCADE parity-check error correction |
| **Depolarizing Channel** | Realistic noise model for quantum transmission |

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install qiskit qiskit-aer numpy cryptography
```

## Usage

### Normal Transfer (No Eavesdropper)

```bash
# Terminal 1: Start Bob (receiver)
python bob.py

# Terminal 2: Send a file as Alice
echo "Top secret quantum message!" > secret.txt
python alice.py secret.txt
```

Bob will receive and decrypt the file as `received_secret.txt`.

### With Eavesdropper (Eve)

```bash
# Terminal 1: Start Bob
python bob.py

# Terminal 2: Start Eve (MITM proxy)
python eve.py

# Terminal 3: Alice connects through Eve
python alice.py secret.txt --eve-mode
```

Eve's interception introduces ~25% QBER, causing the protocol to **abort** — demonstrating quantum security.

## File Structure

| File | Description |
|---|---|
| `config.py` | Shared constants (ports, thresholds, decoy parameters) |
| `quantum_channel.py` | Qubit preparation, noise simulation, Eve's attack |
| `bb84_protocol.py` | Full BB84 engine with decoy states and key distillation |
| `crypto_utils.py` | AES-256-GCM encryption and HKDF key derivation |
| `alice.py` | Sender: QKD → encrypt → transfer |
| `bob.py` | Receiver: QKD → receive → decrypt |
| `eve.py` | Eavesdropper: intercept-resend MITM attack |

## Technologies

- **Python 3.12**
- **Qiskit 2.x** + **Qiskit Aer** — quantum circuit simulation
- **cryptography** — AES-256-GCM + HKDF
- **NumPy** — numerical operations

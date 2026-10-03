# Homework 2

This project runs locally inside the course Ubuntu VM.
The VM uses NAT networking. No network sockets are required.

## Setup

From ~/csce465-agentsec:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography==49.0.0 pytest==9.1.1
cd hw2
```

The submitted ffdhe3072.pem was generated with:

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

## Run

From the hw2 directory:

```bash
python baseline_ctr.py
python handshake.py
python secure_record.py
python -m pytest -v
```

## Files

- baseline_ctr.py: CTR tampering and replay demonstration.
- handshake.py: authenticated finite-field DH and key derivation.
- secure_record.py: encrypt-then-MAC record layer.
- tests/test_security.py: valid-operation and adversarial tests.
- evidence/: actual terminal output.
- report.pdf: explanations and experiment evidence.
- AI_USAGE.md and ai_conversation.txt: AI disclosure and log.

## Design

RSA signing keys are generated once per demonstration process
and reused across sessions in that process.
Trusted peer RSA public keys are supplied directly in the simulation.
Each new session has fresh ephemeral DH private values and nonces.

The record format is:

15-byte header || 16-byte IV || ciphertext || 32-byte HMAC tag

Direction 0 means gateway-to-node.
Direction 1 means node-to-gateway.
Sequence numbers start at zero independently in each direction.

Each party uses one RecordLayer object for the lifetime of a session.
Do not recreate the object with the same keys or reset its sequence state.
The implementation assumes sequential calls, not concurrent senders.

## Limitation

Protected records contain at most 16 plaintext bytes.
The prescribed CTR IV is session_id || sequence.
With consecutive sequence numbers, longer records could overlap
counter blocks across records under the same key.
The implementation rejects longer records.

The mock commands are printed, not executed.

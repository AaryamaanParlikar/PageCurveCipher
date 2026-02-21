# PageCurveCipher — Secure Protocol Implementation

PageCurveCipher is a custom-built secure communication protocol written in Python that demonstrates how real-world encrypted transport systems are architected internally. It incrementally layers cryptographic protections to form a fully authenticated, stateful, forward-secure communication channel.

This project is designed for educational and research purposes to expose the structural logic behind secure protocols such as TLS, SSH, and modern encrypted messaging systems.

---

## Concept Inspiration

The name *PageCurveCipher* is inspired by the **Page Curve** in black hole physics, which describes how information entering a black hole appears random but is actually preserved within hidden correlations.

Similarly, this protocol ensures that intercepted packets appear statistically random unless the observer possesses the correct session state and cryptographic keys.

---

## Protocol Architecture

The protocol is constructed as layered defenses:


Identity Verification
↓
Key Exchange
↓
Session Encryption
↓
Integrity Verification
↓
Replay Protection
↓
Ordering Enforcement
↓
Key Rotation


Each layer protects against a distinct class of attacks.

---

## Implemented Security Features

### Cryptographic Core
- Diffie–Hellman key exchange
- Dynamic session key generation
- SHA-256 key derivation

### Authentication
- RSA-signed server handshake
- Client public-key authentication
- Challenge–response identity verification

### Message Protection
- Stateful stream encryption
- HMAC-based message authentication
- Nonce replay prevention
- Strict sequence number enforcement

### Session Security
- Forward secrecy through ephemeral keys
- Automatic key rotation
- Stateful protocol validation

---

## Packet Format


sequence:nonce|ciphertext||MAC


| Field | Purpose |
|------|--------|
sequence | prevents packet reordering or duplication |
nonce | prevents replay attacks |
ciphertext | encrypted message |
MAC | integrity and authenticity verification |

---

## Handshake Protocol


Client connects
↓
Server sends DH parameters + signature
↓
Client verifies server identity
↓
Client sends DH value
↓
Shared session key derived
↓
Server sends challenge
↓
Client signs challenge
↓
Server verifies client identity
↓
Secure session established


---

## Key Rotation Mechanism

The protocol automatically rotates encryption keys every three packets using a deterministic hash chain:


new_key = SHA256(previous_key)


Both client and server independently compute the new key based on synchronized sequence numbers, eliminating the need for additional key exchange messages.

### Security Benefits

- Limits damage if a session key is compromised
- Reduces cryptanalysis window
- Prevents long-term traffic decryption
- Strengthens forward secrecy properties

This mechanism is conceptually similar to key update systems used in TLS 1.3 and modern secure messaging protocols.

---

## Security Guarantees

| Property | Protection Mechanism |
|--------|----------------------|
Confidentiality | Encryption |
Integrity | HMAC |
Authentication | Digital signatures |
Replay resistance | Nonce tracking |
Ordering enforcement | Sequence numbers |
Forward secrecy | Diffie–Hellman |
Key compromise resistance | Rotation |
MITM resistance | Signed handshake |

---

## Cipher Workflow

Encryption:


Plaintext → Numeric Encoding → Stateful Transformation → Ciphertext


Decryption:


Ciphertext → Reverse Transformation → Numeric Recovery → Plaintext


The cipher state evolves after each symbol, ensuring positional unpredictability.

---

## Running the Project

Start server:

python server.py


Run client:

python client.py


---

## Project Structure


server.py
client.py
server_private.pem
server_public.pem
client_private.pem
authorized_clients/
client_public.pem
README.md


---

## Educational Value

This project demonstrates:

- secure protocol layering
- cryptographic state synchronization
- adversarial resilience design
- session key lifecycle management
- identity verification architecture
- secure packet construction

It is intentionally written without relying on high-level cryptographic frameworks to reveal how secure systems function internally.

---

## Why This Project Is Unique

Most beginner cryptography projects stop at encryption.

PageCurveCipher implements a complete secure communication protocol including:

- full handshake negotiation
- identity verification
- stateful session management
- replay protection
- sequence enforcement
- forward secrecy
- key lifecycle control

This mirrors the architectural design principles of real secure transport protocols.

---

## Future Enhancements

Planned upgrades include:

- intrusion detection system
- certificate authority trust chain
- packet padding against traffic analysis
- binary packet encoding
- multi-client concurrency
- secure logging framework
- session renegotiation

---

## Author

Developed by **Aaryamaan Parlikar** as a practical exploration of secure protocol engineering.

---

## Disclaimer

This project is intended for educational and research purposes only.  
It is not designed for production security deployment.
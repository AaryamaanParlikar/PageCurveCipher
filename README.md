# PageCurveCipher — Secure Protocol Implementation

PageCurveCipher is a custom-built secure communication protocol implemented in Python.  
It demonstrates how real-world secure transport systems are structured internally by layering encryption, authentication, replay protection, key exchange, and identity verification.

---

## Inspiration

This project is conceptually inspired by the theoretical physics concept known as the **Page Curve**, which describes how information entering a black hole appears scrambled and random but is ultimately preserved.

Similarly, this protocol ensures that intercepted packets appear meaningless unless the correct session state, shared secret, and verification mechanisms are known.

---

## Implemented Security Layers

This system incrementally builds a complete secure communication stack:

- Stream-style state-based encryption
- HMAC-based message authentication
- Nonce-based replay protection
- Timestamp expiration window
- Secure TCP framing
- Diffie–Hellman key exchange
- Dynamic per-session keys
- RSA digital signature server authentication

---

## Full Handshake Flow

1. Client connects to server  
2. Server sends Diffie–Hellman parameters (p, g, B)  
3. Server signs handshake values using RSA private key  
4. Client verifies signature using server public key  
5. Client sends its Diffie–Hellman value (A)  
6. Both derive shared session key  
7. Secure communication begins  

---

## Packet Structure

All messages follow this structure:

nonce | ciphertext || MAC


Where:

- **nonce** → prevents replay attacks  
- **ciphertext** → encrypted message  
- **MAC** → verifies integrity and authenticity  

---

## Security Guarantees

| Property | Protection Mechanism |
|----------|----------------------|
Confidentiality | Stream cipher encryption |
Integrity | HMAC authentication |
Authentication | Shared session key |
Freshness | Nonce validation |
Replay Resistance | Nonce tracking |
Forward Secrecy | Diffie–Hellman session keys |
Server Identity | RSA digital signature |

---

## Cipher Workflow

Encryption process:

Plaintext
→ Numeric Conversion
→ State-Based Transformation
→ Ciphertext


Decryption process:

Ciphertext
→ Reverse State Calculation
→ Numeric Recovery
→ Plaintext


The internal state evolves after each character, ensuring positional uniqueness in encryption.

---

## System Architecture Overview

Client
↓
DH Handshake + Signature Verification
↓
Session Key Derivation
↓
Encrypt + MAC + Nonce
↓
Transmit Packet
↓
Server Validation Layers
↓
Decrypt Message
↓
Secure Reply


Each stage must pass validation before processing continues.

---

## Running the Project

Start server:

python server.py


Run client:

python client.py


---

## Key Files

- `server.py` — secure server implementation  
- `client.py` — secure client implementation  
- `server_private.pem` — server signing key (ignored by Git)  
- `server_public.pem` — server verification key  

---

## Educational Value

This project demonstrates:

- secure protocol layering
- adversarial defense design
- replay attack mitigation
- cryptographic key exchange
- identity verification
- state synchronization in encrypted channels

It models the structural logic used in real-world protocols such as TLS and SSH.

---

## Future Improvements

Planned enhancements include:

- Client-side authentication
- Certificate chain validation
- Perfect forward secrecy key rotation
- Packet sequence numbering
- Structured binary packet headers
- Attack logging and anomaly detection
- Multi-client concurrency support

---

## Why This Project Matters

Most beginner cryptography projects stop at encryption and decryption.

PageCurveCipher goes further by modeling a complete secure session protocol with handshake authentication and layered defenses.

It serves as a practical framework for understanding secure transport protocol design.

---

## Author

Developed by **Aaryamaan Parlikar** as a practical exploration of secure protocol engineering.

---

## Disclaimer

This project is intended for educational and research purposes only.  
It is not designed for production security use.
# PageCurveCipher — Secure Protocol Implementation

PageCurveCipher is a custom-built secure communication protocol implemented in Python that demonstrates how real-world encrypted systems are structured internally. It was developed as a hands-on exploration of cryptographic protocol engineering rather than just encryption algorithms.

---

## Inspiration

This project is conceptually inspired by the theoretical physics idea that information entering a black hole appears scrambled and random until enough radiation is collected to reconstruct it.

Similarly, this protocol ensures that intercepted packets appear meaningless unless the correct session state, key, and validation process are known.

---

## Implemented Security Layers

This system incrementally implements real protocol defenses:

- Stream-style encryption
- Message authentication (HMAC)
- Integrity verification
- Nonce-based replay protection
- Timestamp expiration window
- Secure packet framing
- Diffie–Hellman key exchange
- Dynamic session keys

---

## Protocol Packet Structure

Each transmitted message follows:

nonce | ciphertext || MAC


Where:

- **nonce** → prevents replay attacks  
- **ciphertext** → encrypted message  
- **MAC** → verifies authenticity and integrity  

---

## Handshake Process

Before any message is sent, client and server perform a Diffie–Hellman key exchange to generate a shared session key that is never transmitted directly.

This ensures:

- unique key per connection  
- resistance to recorded traffic attacks  
- protection if long-term keys leak  

---

## Security Guarantees Demonstrated

| Property | Protection Mechanism |
|--------|-----------------------|
Confidentiality | Encryption |
Integrity | MAC |
Authentication | Shared secret session key |
Freshness | Nonce |
Replay Resistance | Nonce tracking |
Key Security | Diffie–Hellman |

---

## System Architecture Overview

Client
↓
Encrypt + MAC + Nonce
↓
Transmit Packet
↓
Server Validation Layers
↓
Decrypt Message
↓
Process Request
↓
Encrypt Reply
↓
Client Verification


Each stage must pass validation before the next executes. Invalid packets are silently rejected.

---

## Cipher Workflow

Encryption Process:

Plaintext → Numeric Conversion → State-Based Transformation → Ciphertext


Decryption Process:

Ciphertext → Reverse State Transformation → Numeric Recovery → Plaintext


The cipher state evolves after each character, ensuring identical letters encrypt differently depending on position.

---

## Running the Project

Start server:

python server.py


Run client:

python client.py


---

## Educational Value

This project demonstrates how secure communication protocols are engineered in practice:

- layered security design
- adversarial testing
- defensive validation
- session key negotiation
- protocol state synchronization

It is intentionally written from scratch to illustrate concepts normally hidden inside cryptographic libraries.

---

## Future Improvements

Planned enhancements include:

- Digital signature–based server authentication  
- Perfect forward secrecy key rotation  
- Multi-client concurrent handling  
- Packet sequence numbering  
- Structured packet headers instead of delimiters  
- Certificate verification layer  
- Attack logging and anomaly detection  

These additions would bring the protocol closer to real-world secure transport architectures.

---

## Why This Project Matters

Most beginner cryptography projects stop at encryption and decryption. PageCurveCipher goes further by modeling the structural logic used in real secure protocols such as TLS and SSH, making it a practical learning framework for understanding secure system design.

---

## Status

Current version includes full secure session protocol with key exchange, authentication, replay defense, and message validation.

---

## Author

Developed by **Aaryamaan Parlikar** as a practical exploration of secure protocol engineering.

---

## Disclaimer

This project is for educational and research purposes only and is **not intended for production security use**.

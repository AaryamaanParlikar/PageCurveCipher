# PageCurveCipher

**PageCurveCipher** is a custom secure communication protocol built in Python that demonstrates the internal structure of real-world cryptographic systems. It was designed as a hands-on exploration of how secure protocols actually work beneath the surface, combining encryption, authentication, integrity verification, and replay protection into a single experimental framework.

---

## Inspiration

This project is conceptually inspired by the theoretical physics idea that information thrown into a **black hole** appears scrambled and random until enough radiation is collected to reconstruct it. That thought experiment inspired the design goal:

> Build a system where intercepted data looks meaningless unless the correct key, state, and verification logic are known.

---

## Features

* Custom stream cipher encryption
* HMAC-based message authentication
* Integrity verification
* Nonce-based replay protection
* Time-window nonce expiration
* Secure packet structure validation
* Persistent socket server
* Attack simulation testing modes

---

## Security Properties Demonstrated

This system models the same core guarantees used in real secure protocols:

| Property          | Implementation           |
| ----------------- | ------------------------ |
| Confidentiality   | Stream cipher encryption |
| Integrity         | HMAC verification        |
| Authentication    | Shared secret key        |
| Replay Protection | Nonce tracking           |
| Freshness         | Expiring nonce window    |

---

## Packet Format

```
nonce | ciphertext || MAC
```

**Components**

* **nonce** → prevents replay attacks
* **ciphertext** → encrypted message
* **MAC** → verifies authenticity and integrity

---

## Protocol Architecture

```
Client                                   Server
  |                                        |
  |--- nonce | ciphertext || MAC --------->|
  |                                        |
  |        verify MAC + nonce              |
  |        check replay window             |
  |        decrypt message                 |
  |                                        |
  |<-- nonce | ciphertext || MAC ----------|
  |                                        |
  |        verify + decrypt reply          |
```

---

## Data Flow

**Encryption**

```
Plaintext → numeric encoding → stream cipher → ciphertext
```

**Authentication**

```
nonce + ciphertext → HMAC → MAC
```

**Verification**

```
recompute MAC → compare → accept or reject
```

---

## How It Works

1. Client encrypts message using evolving internal state.
2. Client generates a random nonce.
3. Client computes MAC over nonce + ciphertext.
4. Packet is transmitted.
5. Server verifies integrity and freshness.
6. If valid → decrypts and replies.
7. If invalid → silently rejects.

---

## Running the Project

Start server:

```
python server.py
```

Run client:

```
python client.py
```

Client modes:

```
n → send new encrypted message
r → replay captured packet (testing mode)
```

---

## Attack Simulation Modes

This project intentionally allows testing of adversarial scenarios.

### Replay Attack

Send previously captured packet.

Expected result:

```
Server rejects connection
```

---

### Tampering Attack

Modify any digit in packet.

Expected result:

```
Integrity check fails
```

---

### Invalid Packet

Break packet format.

Expected result:

```
Immediate rejection
```

---

## Security Design Philosophy

The protocol uses layered defenses:

```
Encryption protects secrecy
MAC protects integrity
Nonce protects freshness
Validation protects parsing
```

No single mechanism is trusted alone. Security emerges from combining them.

---

## Why This Project Stands Out

Most beginner encryption projects only show:

```
encrypt → decrypt
```

PageCurveCipher demonstrates real protocol engineering concepts:

* adversarial testing
* replay attack defense
* secure parsing
* state synchronization
* layered security design

This mirrors how actual secure communication systems are built.

---

## Learning Outcomes

Working with this project helps you understand:

* how secure protocols operate internally
* why encryption alone is insufficient
* how replay attacks function
* why authentication must cover all fields
* how defensive validation prevents exploits

---

## Recommended Experiments

Try modifying parameters to observe security effects:

* change nonce lifetime
* disable MAC verification
* reuse nonce intentionally
* alter ciphertext
* modify key value

Each reveals a different security principle.

---

## Future Improvements

Possible extensions:

* multi-client support
* session key negotiation
* challenge–response authentication
* Diffie–Hellman key exchange
* nonlinear cipher transformations

---

## Author

Developed by **Aaryamaan Parlikar** as a practical exploration of secure protocol engineering.

---

## Disclaimer

This project is for educational and research purposes only.
It is **not production-grade cryptography** and should not be used for real-world security.

Its purpose is to demonstrate how secure communication systems are designed, attacked, and defended.

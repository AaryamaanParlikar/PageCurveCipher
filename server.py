import socket
import random
import hashlib
import hmac
import time
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---------- LOAD SERVER PRIVATE KEY ----------
with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# ---------- DIFFIE HELLMAN ----------
p = 2147483647
g = 5

# ---------- NONCE STORAGE ----------
NONCE_LIFETIME = 30
seen_nonces = {}

# ---------- HELPERS ----------

def recvline(conn):
    data = b""
    while not data.endswith(b"\n"):
        part = conn.recv(1)
        if not part:
            break
        data += part
    return data.decode().strip()

def derive_key(shared):
    return hashlib.sha256(str(shared).encode()).digest()

def make_mac(key, data):
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def verify_mac(key, data, mac):
    return hmac.compare_digest(make_mac(key, data), mac)

def clean():
    now = time.time()
    expired = [n for n,t in seen_nonces.items() if now - t > NONCE_LIFETIME]
    for n in expired:
        del seen_nonces[n]

def load_authorized_keys():
    keys = []
    if not os.path.exists("authorized_clients"):
        return keys
    for file in os.listdir("authorized_clients"):
        path = os.path.join("authorized_clients", file)
        with open(path,"rb") as f:
            keys.append(serialization.load_pem_public_key(f.read()))
    return keys

# ---------- START SERVER ----------
server = socket.socket()
server.bind(("0.0.0.0",5000))
server.listen(5)

print("Server running...")

while True:
    conn, addr = server.accept()
    print("Connected:", addr)

    # ----- SIGNED DIFFIE HELLMAN -----
    b = random.randint(2,100000)
    B = pow(g, b, p)

    handshake_data = f"{p},{g},{B}"

    signature = private_key.sign(
        handshake_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    conn.sendall((handshake_data + "|" + signature.hex() + "\n").encode())

    A = int(recvline(conn))

    shared = pow(A, b, p)
    key = derive_key(shared)

    # ----- CLIENT AUTHENTICATION -----
    authorized_keys = load_authorized_keys()

    challenge = str(random.randint(100000,999999))
    conn.sendall((challenge + "\n").encode())

    signature = bytes.fromhex(recvline(conn))

    verified = False
    for pub in authorized_keys:
        try:
            pub.verify(
                signature,
                challenge.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verified = True
            break
        except:
            pass

    if not verified:
        print("Unauthorized client")
        conn.close()
        continue

    print("Client authenticated")

    # ----- RECEIVE PACKET -----
    clean()
    packet = recvline(conn)

    parts = packet.split("||")
    if len(parts) != 2:
        conn.close()
        continue

    data, mac = parts

    if not verify_mac(key, data, mac):
        print("Tampered message")
        conn.close()
        continue

    nonce, cipher = data.split("|")

    if nonce in seen_nonces:
        print("Replay detected")
        conn.close()
        continue

    seen_nonces[nonce] = time.time()

    nums = [int(x) for x in cipher.split(",") if x]
    state = shared % (2**32)

    message = ""
    for c in nums:
        pnum = (c - state) % (2**32)
        state = (state + c) % (2**32)
        message += chr(pnum + 64)

    print("Message:", message)

    # ----- REPLY -----
    reply = "OK"
    nums = [ord(c)-64 for c in reply]

    out = []
    for n in nums:
        c = (n + state) % (2**32)
        state = (state + c) % (2**32)
        out.append(str(c))

    cipher = ",".join(out)
    payload = nonce + "|" + cipher
    mac = make_mac(key, payload)

    conn.sendall((payload + "||" + mac + "\n").encode())
    conn.close()

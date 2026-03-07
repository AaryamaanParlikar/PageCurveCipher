import socket
import random
import hashlib
import hmac
import time
import os
import collections

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# -------- LOAD SERVER PRIVATE KEY --------
with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# -------- DIFFIE HELLMAN --------
p = 2147483647
g = 5

# -------- NONCE STORAGE --------
NONCE_LIFETIME = 30
seen_nonces = {}

# -------- IDS --------
suspicious_ips = {}
blocked_ips = set()

# -------- RATE LIMIT --------
connection_times = collections.defaultdict(list)
MAX_CONNECTIONS = 5
WINDOW_SECONDS = 10


# -------- LOGGING --------
def log_event(event):
    with open("security.log", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {event}\n")


# -------- IDS FLAGGING --------
def flag(ip, reason):
    alert = f"[ALERT] {ip} → {reason}"
    print(alert)
    log_event(alert)

    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    if suspicious_ips[ip] >= 3:
        blocked_ips.add(ip)
        msg = f"[BLOCKED] {ip} banned due to repeated attacks"
        print(msg)
        log_event(msg)


# -------- RATE LIMIT CHECK --------
def rate_limit(ip):
    now = time.time()

    connection_times[ip] = [
        t for t in connection_times[ip]
        if now - t < WINDOW_SECONDS
    ]

    if len(connection_times[ip]) >= MAX_CONNECTIONS:
        return False

    connection_times[ip].append(now)
    return True


# -------- HELPERS --------
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
    expired = [n for n, t in seen_nonces.items() if now - t > NONCE_LIFETIME]
    for n in expired:
        del seen_nonces[n]


def load_authorized_keys():
    keys = []
    if not os.path.exists("authorized_clients"):
        return keys
    for file in os.listdir("authorized_clients"):
        path = os.path.join("authorized_clients", file)
        with open(path, "rb") as f:
            keys.append(serialization.load_pem_public_key(f.read()))
    return keys


# -------- SERVER --------
server = socket.socket()
server.bind(("0.0.0.0", 5000))
server.listen(5)

print("Server running...")

while True:

    conn, addr = server.accept()
    ip = addr[0]

    if ip in blocked_ips:
        print("Blocked IP tried reconnect:", ip)
        conn.close()
        continue

    if not rate_limit(ip):
        msg = f"[RATE LIMIT] Too many connections from {ip}"
        print(msg)
        log_event(msg)
        conn.close()
        continue

    print("Connected:", addr)

    # ----- SIGNED DH -----
    b = random.randint(2, 100000)
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

    try:
        A = int(recvline(conn))
    except:
        flag(ip, "Invalid DH value")
        conn.close()
        continue

    shared = pow(A, b, p)
    key = derive_key(shared)
    state = shared % (2**32)

    # ----- CLIENT AUTH -----
    authorized_keys = load_authorized_keys()

    challenge = str(random.randint(100000, 999999))
    conn.sendall((challenge + "\n").encode())

    try:
        signature = bytes.fromhex(recvline(conn))
    except:
        flag(ip, "Invalid signature format")
        conn.close()
        continue

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
        flag(ip, "Invalid client signature")
        conn.close()
        continue

    print("Client authenticated")

    expected_seq = 1

    clean()
    packet = recvline(conn)

    parts = packet.split("||")

    if len(parts) != 2:
        flag(ip, "Malformed packet")
        conn.close()
        continue

    data, mac = parts

    if not verify_mac(key, data, mac):
        flag(ip, "MAC mismatch")
        conn.close()
        continue

    seq_part, rest = data.split(":", 1)
    seq = int(seq_part)

    if seq != expected_seq:
        flag(ip, "Sequence violation")
        conn.close()
        continue

    expected_seq += 1

    if seq % 3 == 0:
        key = hashlib.sha256(key).digest()
        print("Key rotated")

    nonce, cipher = rest.split("|")

    if nonce in seen_nonces:
        flag(ip, "Replay attack")
        conn.close()
        continue

    seen_nonces[nonce] = time.time()

    nums = [int(x) for x in cipher.split(",") if x]

    message = ""

    for c in nums:
        pnum = (c - state) % (2**32)
        state = (state + c) % (2**32)
        message += chr(pnum + 64)

    print("Message:", message)

    # ----- REPLY -----
    reply = "OK"
    nums = [ord(c) - 64 for c in reply]

    out = []

    for n in nums:
        c = (n + state) % (2**32)
        state = (state + c) % (2**32)
        out.append(str(c))

    cipher = ",".join(out)

    payload = str(expected_seq) + ":" + nonce + "|" + cipher
    mac = make_mac(key, payload)

    conn.sendall((payload + "||" + mac + "\n").encode())
    conn.close()
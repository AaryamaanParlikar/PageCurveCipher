import socket
import random
import hashlib
import hmac
import time

p = 2147483647
g = 5

NONCE_LIFETIME = 30
seen_nonces = {}

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
    expired = [n for n,t in seen_nonces.items() if now-t > NONCE_LIFETIME]
    for n in expired:
        del seen_nonces[n]

server = socket.socket()
server.bind(("0.0.0.0",5000))
server.listen(5)

print("Server running...")

while True:
    conn,addr = server.accept()
    print("Connected:",addr)

    # ---- Diffie Hellman ----
    b = random.randint(2,100000)
    B = pow(g,b,p)

    conn.sendall(f"{p},{g},{B}\n".encode())

    A = int(recvline(conn))

    shared = pow(A,b,p)
    key = derive_key(shared)

    # ---- receive packet ----
    clean()
    packet = recvline(conn)

    parts = packet.split("||")
    if len(parts)!=2:
        conn.close()
        continue

    data,mac = parts

    if not verify_mac(key,data,mac):
        print("Tampered message")
        conn.close()
        continue

    nonce,cipher = data.split("|")

    if nonce in seen_nonces:
        print("Replay detected")
        conn.close()
        continue

    seen_nonces[nonce]=time.time()

    nums=[int(x) for x in cipher.split(",") if x]
    state = shared % (2**32)

    msg=""
    for c in nums:
        pnum=(c-state)%(2**32)
        state=(state+c)%(2**32)
        msg+=chr(pnum+64)

    print("Message:",msg)

    # ---- reply ----
    reply="OK"
    nums=[ord(c)-64 for c in reply]

    out=[]
    for n in nums:
        c=(n+state)%(2**32)
        state=(state+c)%(2**32)
        out.append(str(c))

    cipher=",".join(out)
    payload=nonce+"|"+cipher
    mac=make_mac(key,payload)

    conn.sendall((payload+"||"+mac+"\n").encode())
    conn.close()

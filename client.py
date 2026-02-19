import socket
import random
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---------- LOAD KEYS ----------
with open("server_public.pem","rb") as f:
    server_pub = serialization.load_pem_public_key(f.read())

with open("client_private.pem","rb") as f:
    client_priv = serialization.load_pem_private_key(f.read(), password=None)

# ---------- HELPERS ----------

def recvline(sock):
    data = b""
    while not data.endswith(b"\n"):
        part = sock.recv(1)
        if not part:
            break
        data += part
    return data.decode().strip()

def derive_key(shared):
    return hashlib.sha256(str(shared).encode()).digest()

def make_mac(key,data):
    return hmac.new(key,data.encode(),hashlib.sha256).hexdigest()

def verify_mac(key,data,mac):
    return hmac.compare_digest(make_mac(key,data),mac)

# ---------- CONNECT ----------
client = socket.socket()
client.connect(("127.0.0.1",5000))

# ----- SIGNED DH -----
line = recvline(client)
data, signature_hex = line.split("|")

signature = bytes.fromhex(signature_hex)

server_pub.verify(
    signature,
    data.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

p,g,B = map(int,data.split(","))

# ----- SEND DH -----
a = random.randint(2,100000)
A = pow(g,a,p)
client.sendall((str(A)+"\n").encode())

shared = pow(B,a,p)
key = derive_key(shared)
state = shared % (2**32)

# ----- CLIENT AUTH -----
challenge = recvline(client)

signature = client_priv.sign(
    challenge.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

client.sendall((signature.hex()+"\n").encode())

# ----- SEND MESSAGE -----
seq = 1

msg = input("Message: ").upper()
nums = [ord(c)-64 for c in msg]

out = []
for n in nums:
    c = (n + state) % (2**32)
    state = (state + c) % (2**32)
    out.append(str(c))

cipher = ",".join(out)
nonce = str(secrets.randbits(32))
payload = str(seq) + ":" + nonce + "|" + cipher
mac = make_mac(key,payload)

client.sendall((payload+"||"+mac+"\n").encode())

seq += 1

# ----- KEY ROTATION (SYNCED) -----
if (seq-1) % 3 == 0:
    key = hashlib.sha256(key).digest()
    print("Key rotated")

# ----- RECEIVE REPLY -----
reply = recvline(client)
data, mac = reply.split("||")

if not verify_mac(key,data,mac):
    print("Tampered reply")
    exit()

seq_part, rest = data.split(":",1)
nonce, cipher = rest.split("|")

nums = [int(x) for x in cipher.split(",") if x]

msg = ""
for c in nums:
    pnum = (c - state) % (2**32)
    state = (state + c) % (2**32)
    msg += chr(pnum + 64)

print("Server:", msg)

client.close()

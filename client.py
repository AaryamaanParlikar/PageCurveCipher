import socket
import random
import hashlib
import hmac
import secrets
from colorama import Fore, Style, init

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

init()

PORT = 5000


def recvline(sock):
    data = b""
    while not data.endswith(b"\n"):
        data += sock.recv(1)
    return data.decode().strip()


def derive_key(shared):
    return hashlib.sha256(str(shared).encode()).digest()


def make_mac(key, data):
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


with open("server_public.pem", "rb") as f:
    server_pub = serialization.load_pem_public_key(f.read())

client = socket.socket()
client.connect(("127.0.0.1", PORT))

print(Fore.CYAN + "\n════ CLIENT STARTED ════\n")

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

p, g, B = map(int, data.split(","))

print(Fore.GREEN + "✓ Server authenticated")

a = random.randint(2, 100000)
A = pow(g, a, p)

client.sendall((str(A) + "\n").encode())

shared = pow(B, a, p)

key = derive_key(shared)
state = shared % (2**32)

print(Fore.GREEN + "✓ Session key established")

msg = input(Fore.YELLOW + "\nEnter message: ").upper()

print(Fore.CYAN + "\n════════ CLIENT PIPELINE ════════")

print("Plaintext        :", msg)

nums = [ord(c) - 64 for c in msg]

print("Numeric Encoding :", nums)

cipher_nums = []

for n in nums:
    c = (n + state) % (2**32)
    state = (state + c) % (2**32)
    cipher_nums.append(c)

cipher = ",".join(map(str, cipher_nums))

print("Ciphertext       :", cipher_nums)

nonce = str(secrets.randbits(32))

payload = "1:" + nonce + "|" + cipher

mac = make_mac(key, payload)

packet = payload + "||" + mac

print("\nNonce            :", nonce)
print("MAC              :", mac[:16] + "...")

print(Fore.MAGENTA + "\nPacket →")
print(packet)

print(Fore.CYAN + "════════════════════════════════\n")

client.sendall((packet + "\n").encode())

reply = recvline(client)

print(Fore.CYAN + "\nServer response packet:")
print(reply)

client.close()
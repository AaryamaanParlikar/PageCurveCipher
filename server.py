import socket
import random
import hashlib
import hmac
from colorama import Fore, Style, init

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

init()

PORT = 5000


def recvline(conn):
    data = b""
    while not data.endswith(b"\n"):
        data += conn.recv(1)
    return data.decode().strip()


def derive_key(shared):
    return hashlib.sha256(str(shared).encode()).digest()


def make_mac(key, data):
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


def verify_mac(key, data, mac):
    return hmac.compare_digest(make_mac(key, data), mac)


with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

p = 2147483647
g = 5

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind(("0.0.0.0", PORT))
server.listen(5)

print(Fore.CYAN + "\n════ SERVER STARTED ════\n")

while True:

    conn, addr = server.accept()

    print(Fore.YELLOW + "Client connected:", addr)

    b = random.randint(2, 100000)

    B = pow(g, b, p)

    handshake = f"{p},{g},{B}"

    signature = private_key.sign(
        handshake.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    conn.sendall((handshake + "|" + signature.hex() + "\n").encode())

    A = int(recvline(conn))

    shared = pow(A, b, p)

    key = derive_key(shared)

    state = shared % (2**32)

    print(Fore.GREEN + "✓ Handshake complete")

    packet = recvline(conn)

    print(Fore.CYAN + "\n════════ PACKET INSPECTION ════════")

    print("Packet received:")
    print(packet)

    data, mac = packet.split("||")

    if verify_mac(key, data, mac):
        print(Fore.GREEN + "\nIntegrity Check  : ✓ MAC VALID")
    else:
        print(Fore.RED + "\nIntegrity Check  : ✗ MAC INVALID")

    seq_part, rest = data.split(":", 1)

    nonce, cipher = rest.split("|")

    nums = [int(x) for x in cipher.split(",")]

    print(Fore.YELLOW + "\nCiphertext       :", nums)

    decoded = []
    message = ""

    for c in nums:
        pnum = (c - state) % (2**32)
        state = (state + c) % (2**32)
        decoded.append(pnum)
        message += chr(pnum + 64)

    print("Recovered Values :", decoded)
    print(Fore.GREEN + "Decoded Message  :", message)

    print(Fore.CYAN + "══════════════════════════════════\n")

    conn.close()
import socket
import hmac
import hashlib
import secrets

K = 13
KEY_BYTES = str(K).encode()
MOD = 2**32


def init_state():
    return (K * 7) % MOD


def make_mac(data):
    return hmac.new(KEY_BYTES, data.encode(), hashlib.sha256).hexdigest()


def verify_mac(data, mac):
    expected = make_mac(data)
    return hmac.compare_digest(expected, mac)


def encrypt_stream(nums, state):
    out = []
    for p in nums:
        c = (p + state) % MOD
        state = (state + c + K) % MOD
        out.append(c)
    return out, state


def decrypt_stream(nums, state):
    out = []
    for c in nums:
        p = (c - state) % MOD
        state = (state + c + K) % MOD
        out.append(p)
    return out, state


def letters_to_nums(text):
    return [ord(c) - 64 for c in text]


def nums_to_letters(nums):
    return "".join(chr(n + 64) for n in nums)


client = socket.socket()
client.connect(("127.0.0.1", 5000))

state = init_state()

mode = input("Send new (n) or Simulate attack (r)? ").lower()

if mode == "r":
    packet = input("Paste packet: ")

else:
    msg = input("Enter message: ").upper()

    nums = letters_to_nums(msg)
    cipher, state = encrypt_stream(nums, state)
    cipher_str = ",".join(map(str, cipher))

    nonce = str(secrets.randbits(32))

    payload = nonce + "|" + cipher_str
    mac = make_mac(payload)

    packet = payload + "||" + mac

    print("\nSending packet:")
    print(packet)

client.sendall(packet.encode())

reply = client.recv(4096).decode()
print("\nRAW REPLY:", reply)

parts = reply.split("||")
if len(parts) != 2:
    print("No reply or rejected by server")
    exit()

data, mac = parts

if not verify_mac(data, mac):
    print("SERVER MESSAGE TAMPERED")
    exit()

nonce_recv, cipher_text = data.split("|")

cipher_nums = [int(x) for x in cipher_text.split(",") if x]

plain_reply, state = decrypt_stream(cipher_nums, state)

print("\nServer replied:", nums_to_letters(plain_reply))
print("Reply nonce:", nonce_recv)

client.close()

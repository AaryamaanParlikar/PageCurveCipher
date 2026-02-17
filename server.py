import socket
import hmac
import hashlib
import time

K = 13
KEY_BYTES = str(K).encode()
MOD = 2**32

NONCE_LIFETIME = 30  # seconds
seen_nonces = {}  # nonce → timestamp


def init_state():
    return (K * 7) % MOD


def make_mac(data):
    return hmac.new(KEY_BYTES, data.encode(), hashlib.sha256).hexdigest()


def verify_mac(data, mac):
    expected = make_mac(data)
    return hmac.compare_digest(expected, mac)


def clean_old_nonces():
    now = time.time()
    expired = [n for n, t in seen_nonces.items() if now - t > NONCE_LIFETIME]
    for n in expired:
        del seen_nonces[n]


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


server = socket.socket()
server.bind(("0.0.0.0", 5000))
server.listen(5)

print("Server running...")

while True:
    conn, addr = server.accept()
    print("\nConnected:", addr)

    clean_old_nonces()  # remove expired entries
    state = init_state()

    try:
        packet = conn.recv(4096).decode()
        print("RAW:", packet)

        parts = packet.split("||")
        if len(parts) != 2:
            print("Invalid format")
            conn.close()
            continue

        data, mac = parts

        if not verify_mac(data, mac):
            print("MESSAGE TAMPERED")
            conn.close()
            continue

        nonce, cipher_text = data.split("|")

        now = time.time()
        if nonce in seen_nonces:
            print("REPLAY DETECTED")
            conn.close()
            continue

        seen_nonces[nonce] = now

        cipher_nums = [int(x) for x in cipher_text.split(",") if x]

        plain_nums, state = decrypt_stream(cipher_nums, state)
        message = nums_to_letters(plain_nums)

        print("Message:", message)

        reply = "OK"
        nums = letters_to_nums(reply)

        enc, state = encrypt_stream(nums, state)
        cipher = ",".join(map(str, enc))

        payload = nonce + "|" + cipher
        mac_reply = make_mac(payload)

        conn.sendall((payload + "||" + mac_reply).encode())

    except Exception as e:
        print("Error:", e)

    conn.close()

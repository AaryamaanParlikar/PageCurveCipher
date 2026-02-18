import socket
import random
import hashlib
import hmac
import secrets

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

client=socket.socket()
client.connect(("127.0.0.1",5000))

# ---- receive DH params ----
p,g,B = map(int, recvline(client).split(","))

a=random.randint(2,100000)
A=pow(g,a,p)

client.sendall((str(A)+"\n").encode())

shared=pow(B,a,p)
key=derive_key(shared)

state = shared%(2**32)

msg=input("Message: ").upper()

nums=[ord(c)-64 for c in msg]

out=[]
for n in nums:
    c=(n+state)%(2**32)
    state=(state+c)%(2**32)
    out.append(str(c))

cipher=",".join(out)
nonce=str(secrets.randbits(32))
payload=nonce+"|"+cipher
mac=make_mac(key,payload)

client.sendall((payload+"||"+mac+"\n").encode())

# ---- receive reply ----
reply=recvline(client)

parts=reply.split("||")
if len(parts)!=2:
    print("Invalid reply")
    exit()

data,mac=parts

if not verify_mac(key,data,mac):
    print("Tampered reply")
    exit()

nonce,cipher=data.split("|")

nums=[int(x) for x in cipher.split(",") if x]

msg=""
for c in nums:
    pnum=(c-state)%(2**32)
    state=(state+c)%(2**32)
    msg+=chr(pnum+64)

print("Server:",msg)

client.close()

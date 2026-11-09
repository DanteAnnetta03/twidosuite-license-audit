import socket, json, time, sys

sock_path = sys.argv[1]
out_path = sys.argv[2]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
f = s.makefile("rwb")

def recv_one():
    line = f.readline()
    return json.loads(line) if line else None

recv_one()  # greeting

def send(cmd):
    f.write((json.dumps(cmd) + "\n").encode())
    f.flush()
    return recv_one()

send({"execute": "qmp_capabilities"})
r = send({"execute": "screendump", "arguments": {"filename": out_path}})
print(r)

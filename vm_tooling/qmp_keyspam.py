import socket, json, time, sys

sock_path = sys.argv[1]
duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.15

s = None
for attempt in range(100):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        break
    except (ConnectionRefusedError, ConnectionResetError, FileNotFoundError):
        s.close()
        s = None
        time.sleep(0.05)
if s is None:
    print("no se pudo conectar al socket QMP")
    sys.exit(1)
f = s.makefile("rwb")

def recv_one():
    line = f.readline()
    return json.loads(line) if line else None

greeting = recv_one()
print("greeting:", greeting, flush=True)

def send(cmd):
    f.write((json.dumps(cmd) + "\n").encode())
    f.flush()
    return recv_one()

r = send({"execute": "qmp_capabilities"})
print("capabilities:", r, flush=True)

start = time.time()
count = 0
while time.time() - start < duration:
    send({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": "ret"}]}})
    count += 1
    time.sleep(interval)

print(f"sent {count} keypresses over {duration}s", flush=True)

import socket, json, time, sys

sock_path = sys.argv[1]
out_dir = sys.argv[2]
n_frames = int(sys.argv[3])
interval = float(sys.argv[4])

s = None
for attempt in range(100):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        break
    except (ConnectionRefusedError, ConnectionResetError, FileNotFoundError):
        s.close(); s = None; time.sleep(0.05)
f = s.makefile("rwb")
def recv_one():
    line = f.readline()
    return json.loads(line) if line else None
recv_one()
def send(cmd):
    f.write((json.dumps(cmd) + "\n").encode()); f.flush(); return recv_one()
send({"execute": "qmp_capabilities"})

t0 = time.time()
for i in range(n_frames):
    target = t0 + i * interval
    now = time.time()
    if target > now:
        time.sleep(target - now)
    elapsed = time.time() - t0
    fn = f"{out_dir}/frame_{i:03d}_{elapsed:.2f}s.ppm"
    send({"execute": "screendump", "arguments": {"filename": fn}})
print("listo")

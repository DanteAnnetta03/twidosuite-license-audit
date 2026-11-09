import socket, json, time, sys

class QMP:
    def __init__(self, sock_path, retries=100, delay=0.05):
        s = None
        for _ in range(retries):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock_path)
                break
            except (ConnectionRefusedError, ConnectionResetError, FileNotFoundError):
                s.close(); s = None; time.sleep(delay)
        if s is None:
            raise RuntimeError("no se pudo conectar a QMP")
        self.f = s.makefile("rwb")
        self._recv()
        self.send({"execute": "qmp_capabilities"})

    def _recv(self):
        line = self.f.readline()
        return json.loads(line) if line else None

    def send(self, cmd):
        self.f.write((json.dumps(cmd) + "\n").encode())
        self.f.flush()
        return self._recv()

    def key(self, qcode):
        return self.send({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": qcode}]}})

    def screendump(self, path):
        return self.send({"execute": "screendump", "arguments": {"filename": path}})

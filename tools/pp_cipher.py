#!/usr/bin/env python3
"""
Reimplementacion en Python del cifrado pp_encrypt/pp_decrypt de
BrickLicenceManager.dll (fcn.1005078b), reconstruido por ingenieria
inversa estatica (radare2) a partir del binario original.

seed_func = fcn.1005074c (checksum simple de la password)
cipher    = fcn.1005078b (keystream XOR posicional + rotacion de password)
"""


def c_idiv(a: int, b: int):
    """Division/modulo estilo x86 IDIV: trunca hacia cero (no floor como Python)."""
    q = int(a / b)  # trunca hacia cero en Python 3 con division real
    r = a - q * b
    return q, r


def to_i32(x: int) -> int:
    x &= 0xFFFFFFFF
    if x >= 0x80000000:
        x -= 0x100000000
    return x


def seed_func(password: bytes) -> int:
    """fcn.1005074c"""
    if len(password) < 3 or password[0] == 0 or password[1] == 0 or password[2] == 0:
        return -1
    eax = 1
    ecx = 0
    while ecx < len(password) and password[ecx] != 0:
        dl = password[ecx]
        # movsx edx, dl  (dl es byte con signo en la instruccion original)
        edx = dl if dl < 128 else dl - 256
        edx += ecx
        eax = to_i32(eax + edx)
        ecx += 1
    limit = 0x989680  # 10,000,000
    while eax < limit:
        eax = to_i32(eax + eax)
    return eax


def pp_cipher(data: bytes, password: bytes) -> bytes:
    """fcn.1005078b - funcion compartida por pp_encrypt y pp_decrypt (es su propia inversa)."""
    n = len(data)
    pwlen = len(password)
    if n == 0 or pwlen < 3:
        return b""

    seed_val = seed_func(password)
    q1, r1 = c_idiv(seed_val, 997)
    q2 = to_i32(q1 - 1)
    q3, r2 = c_idiv(q2, 254)
    K = to_i32(r2 + 1)

    out = bytearray(n)
    ecx = 0          # indice rotatorio de password (0..pwlen inclusive, pwlen = byte nulo)
    edx = K
    esi = -n

    for i in range(n):
        tmp = esi + edx - 1
        q, r = c_idiv(tmp, 254)
        edx = r
        al = password[ecx] if ecx < pwlen else 0  # password[pwlen] = terminador nulo
        bl = data[i]
        al ^= bl
        edx = to_i32(edx + 1)
        al ^= (edx & 0xFF)
        al &= 0xFF
        if al == 0:
            al = bl
        out[i] = al & 0xFF

        if ecx < pwlen:
            ecx += 1
        else:
            ecx = 0
        esi += 1

    return bytes(out)


if __name__ == "__main__":
    import sys

    license_path = sys.argv[1] if len(sys.argv) > 1 else "Brk1License.dat"
    password = sys.argv[2].encode() if len(sys.argv) > 2 else b"VDSV42LF"

    with open(license_path, "rb") as f:
        data = f.read()

    print(f"[*] Archivo: {license_path} ({len(data)} bytes)")
    print(f"[*] Password candidata: {password!r}")
    print(f"[*] seed_func(password) = {seed_func(password)}")

    result = pp_cipher(data, password)
    print(f"[*] Resultado ({len(result)} bytes):")
    print(result[:200])
    print()
    print("Hexdump (primeros 128 bytes):")
    for i in range(0, min(128, len(result)), 16):
        chunk = result[i:i+16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{i:04x}  {hexs:<48}  {ascii_s}")

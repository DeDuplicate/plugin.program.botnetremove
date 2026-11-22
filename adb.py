"""Minimal pure-Python ADB client, so the add-on can open a shell on the box's own adbd
(127.0.0.1:5555) without root, an adb binary, or third-party modules.

Self-check:   python adb.py
Live test:    python adb.py 192.168.1.50:5555
"""
import base64
import os
import random
import socket
import struct

CNXN, AUTH, OPEN, OKAY, CLSE, WRTE = (struct.unpack('<I', c)[0] for c in
                                      (b'CNXN', b'AUTH', b'OPEN', b'OKAY', b'CLSE', b'WRTE'))
AUTH_SIGNATURE, AUTH_RSAPUBLICKEY = 2, 3
SHA1_DIGESTINFO = bytes.fromhex('3021300906052b0e03021a05000414')
SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** .5) + 1, 2))]
_rand = random.SystemRandom()


def _is_prime(n, rounds=16):
    if any(n % p == 0 for p in SMALL_PRIMES):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):  # Miller-Rabin
        x = pow(_rand.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits=1024):
    while True:
        n = _rand.getrandbits(bits) | (3 << (bits - 2)) | 1  # top 2 bits set: p*q is exactly 2048 bits
        if (n - 1) % 65537 and _is_prime(n):
            return n


def new_key():
    """2048-bit RSA key (the only size adbd accepts)."""
    p, q = _prime(), _prime()
    return {'n': p * q, 'd': pow(65537, -1, (p - 1) * (q - 1))}


def pubkey(n, name=b'kodi@botnetremove'):
    """Android RSAPublicKey struct (the adb_keys format): words, n0inv, n, R^2 mod n, e."""
    blob = (struct.pack('<II', 64, -pow(n, -1, 1 << 32) & 0xFFFFFFFF) + n.to_bytes(256, 'little')
            + pow(2, 4096, n).to_bytes(256, 'little') + struct.pack('<I', 65537))
    return base64.b64encode(blob) + b' ' + name + b'\x00'


def sign(key, token):
    """PKCS#1 v1.5 signature with the 20-byte token taken as a SHA-1 digest, as adbd verifies it."""
    em = b'\x00\x01' + b'\xff' * (253 - len(SHA1_DIGESTINFO) - len(token)) + b'\x00' + SHA1_DIGESTINFO + token
    return pow(int.from_bytes(em, 'big'), key['d'], key['n']).to_bytes(256, 'big')


class Adb:
    def __init__(self, host='127.0.0.1', port=5555, on_prompt=lambda: None):
        """on_prompt() runs when the user must press "Allow" on the device's debugging prompt."""
        self.s = socket.create_connection((host, port), timeout=10)
        self.last_id = 0
        self._send(CNXN, 0x01000000, 256 * 1024, b'host::\x00')
        cmd, _, _, data = self._recv()
        # ponytail: fresh key every run (nothing on disk for other apps to steal); the user
        # presses Allow each time. Persist it in addon_data if that gets annoying.
        key = new_key() if cmd == AUTH else None
        if cmd == AUTH:  # 1st challenge: signature (unknown key, so adbd re-challenges)
            self._send(AUTH, AUTH_SIGNATURE, 0, sign(key, data))
            cmd, _, _, data = self._recv()
        if cmd == AUTH:  # 2nd challenge: offer the public key, adbd shows "Allow USB debugging?"
            self._send(AUTH, AUTH_RSAPUBLICKEY, 0, pubkey(key['n']))
            on_prompt()
            self.s.settimeout(120)
            cmd, _, _, data = self._recv()
        if cmd != CNXN:
            raise ConnectionError('ADB access was not allowed on the device')
        self.s.settimeout(600)  # find/sha256sum over /system can be silent for a while

    def shell(self, cmd):
        self.last_id += 1
        me, them, out = self.last_id, None, []
        self._send(OPEN, me, 0, b'shell:' + cmd.encode() + b'\x00')
        while True:
            c, a0, a1, data = self._recv()
            if a1 != me:
                continue  # late packet from an earlier stream
            if c == OKAY:
                them = a0
            elif c == WRTE:
                out.append(data)
                self._send(OKAY, me, a0)
            elif c == CLSE:
                if them is not None:
                    self._send(CLSE, me, them)
                break
        return b''.join(out).decode('utf-8', 'replace').replace('\r\n', '\n')

    def close(self):
        self.s.close()

    def _send(self, cmd, a0, a1, data=b''):
        self.s.sendall(struct.pack('<6I', cmd, a0, a1, len(data), sum(data) & 0xFFFFFFFF, cmd ^ 0xFFFFFFFF) + data)

    def _recv(self):
        cmd, a0, a1, n, _, _ = struct.unpack('<6I', self._read(24))
        return cmd, a0, a1, self._read(n)

    def _read(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('adbd closed the connection')
            buf += chunk
        return bytes(buf)


if __name__ == '__main__':
    import sys
    import time
    t = time.time()
    k = new_key()
    print(f'keygen {time.time() - t:.1f}s')
    assert k['n'].bit_length() == 2048
    tok = os.urandom(20)
    em = pow(int.from_bytes(sign(k, tok), 'big'), 65537, k['n']).to_bytes(256, 'big')
    assert em.startswith(b'\x00\x01\xff') and em.endswith(b'\x00' + SHA1_DIGESTINFO + tok)
    if len(sys.argv) > 1:
        h, _, p = sys.argv[1].partition(':')
        a = Adb(h, int(p or 5555), lambda: print('press Allow on the device...'))
        print(a.shell('getprop ro.product.model; id'))
        a.close()
    print('ok')

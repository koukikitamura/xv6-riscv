#!/usr/bin/env python3
"""Check the exact C implementation against hashlib/HMAC, including boundaries."""
import ctypes
import hashlib
import hmac
from pathlib import Path
import random
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
rng = random.Random(8018)
with tempfile.TemporaryDirectory(prefix="xv6-password-") as tmp:
    libpath = Path(tmp) / "password.so"
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    "-O2", str(root / "user/password.c"), "-o", str(libpath)], check=True)
    lib = ctypes.CDLL(str(libpath))
    p = ctypes.c_char_p
    n = ctypes.c_uint
    lib.sha256.argtypes = [p, n, p]
    lib.hmac256.argtypes = [p, n, p, n, p]
    lib.password_hash.argtypes = [p, p, n, p]
    out = ctypes.create_string_buffer(32)
    for length in [0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 1024, 1000000]:
        data = rng.randbytes(length)
        lib.sha256(data, length, out)
        assert out.raw == hashlib.sha256(data).digest(), ("SHA-256", length)
    for keylen in [0, 1, 32, 63, 64, 65, 131]:
        for length in [0, 3, 55, 56, 64, 1000]:
            key, data = rng.randbytes(keylen), rng.randbytes(length)
            lib.hmac256(key, keylen, data, length, out)
            assert out.raw == hmac.digest(key, data, "sha256"), ("HMAC", keylen, length)
    for length in [0, 1, 63]:
        password = b"p" * length
        for rounds in [1, 2, 4096, 100000]:
            salt = rng.randbytes(16)
            lib.password_hash(password, salt, rounds, out)
            assert out.raw == hashlib.pbkdf2_hmac("sha256", password, salt, rounds), (length, rounds)
print("PASS: SHA-256, HMAC, PBKDF2 (66 reference comparisons)")

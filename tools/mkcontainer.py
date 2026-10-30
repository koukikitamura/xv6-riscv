#!/usr/bin/env python3
"""Build a flat xv6 archive: 8-byte magic, LE count, (name[16], LE size, bytes).
Only regular files with single-component xv6 names are accepted. Debug and
symbol tables are omitted from ELF files; the loadable program is unchanged.
"""
import pathlib
import struct
import subprocess
import sys
import tempfile

out, objcopy, *paths = sys.argv[1:]
records = []
names = set()

with tempfile.TemporaryDirectory() as tmp:
    for source in paths:
        path = pathlib.Path(source)
        name = path.name.removeprefix("_")
        if not 0 < len(name.encode()) <= 14 or name in names or name in (".", ".."):
            raise SystemExit(f"invalid image name: {name}")
        names.add(name)

        data = path.read_bytes()
        if data.startswith(b"\x7fELF"):
            stripped = pathlib.Path(tmp) / name
            subprocess.run([objcopy, "--strip-all", str(path), str(stripped)], check=True)
            data = stripped.read_bytes()

        records.append(struct.pack("<16sI", name.encode(), len(data)) + data)

data = b"XV6IMG1\0" + struct.pack("<I", len(records)) + b"".join(records)
if len(data) > (12 + 256) * 1024:
    raise SystemExit("image exceeds xv6 MAXFILE")

pathlib.Path(out).write_bytes(data)
print(f"container image: {len(records)} files, {len(data)} bytes")

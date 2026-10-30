#!/usr/bin/env python3
"""Generate the fixed lab accounts; passwords deliberately equal usernames."""
import hashlib
from pathlib import Path
import re
import secrets
import struct

REPOSITORY = Path(__file__).resolve().parents[1]
OUTPUT = REPOSITORY / "lab"

# These layouts match the records in user/accounts.h.
ACCOUNT_RECORD = struct.Struct("<16sII16s")
CREDENTIAL_RECORD = struct.Struct("<II16s32s")
GROUP_RECORD = struct.Struct("<16sI")

USERS = [
    ("root", 0, 0, "/"),
    ("alice", 1000, 100, "/alice"),
    ("bob", 1001, 100, "/bob"),
    ("carol", 1002, 200, "/carol"),
]

GROUPS = [
    ("root", 0),
    ("users", 100),
    ("guests", 200),
]


def write_accounts(rounds):
    with (OUTPUT / "passwd").open("wb") as public:
        with (OUTPUT / "shadow").open("wb") as private:
            for name, uid, gid, home in USERS:
                account = ACCOUNT_RECORD.pack(
                    name.encode(), uid, gid, home.encode()
                )
                public.write(account)

                # Demonstration passwords equal usernames. Salts differ per user.
                salt = secrets.token_bytes(16)
                password = name.encode()
                digest = hashlib.pbkdf2_hmac("sha256", password, salt, rounds)

                credential = CREDENTIAL_RECORD.pack(uid, rounds, salt, digest)
                private.write(credential)


def write_groups():
    with (OUTPUT / "group").open("wb") as groups:
        for name, gid in GROUPS:
            record = GROUP_RECORD.pack(name.encode(), gid)
            groups.write(record)


def main():
    OUTPUT.mkdir(exist_ok=True)

    header = (REPOSITORY / "user/password.h").read_text()
    definition = re.search(r"#define PASSWORD_ROUNDS\s+(\d+)", header)
    rounds = int(definition[1])

    write_accounts(rounds)
    write_groups()


if __name__ == "__main__":
    main()

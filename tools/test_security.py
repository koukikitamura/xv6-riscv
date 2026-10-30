#!/usr/bin/env python3
"""Boot the real login flow; use a private disk copy and preserve transcripts."""
import argparse
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

class VM:
    def __init__(self, disk, log, cpus=3):
        self.proc = subprocess.Popen([
            "qemu-system-riscv64", "-machine", "virt", "-bios", "none",
            "-kernel", str(ROOT / "kernel/kernel"), "-m", "128M", "-smp", str(cpus),
            "-nographic", "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={disk},if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.pending = b""
        self.log = open(log, "wb")

    def expect(self, needle, timeout=30):
        needle = needle.encode()
        end = time.monotonic() + timeout
        while needle not in self.pending:
            if time.monotonic() >= end:
                raise AssertionError(f"timeout waiting for {needle!r}: {self.pending[-2000:]!r}")
            ready, _, _ = select.select([self.proc.stdout], [], [], min(1, end-time.monotonic()))
            if ready:
                data = os.read(self.proc.stdout.fileno(), 65536)
                if not data:
                    raise AssertionError(f"QEMU exited: {self.pending!r}")
                self.log.write(data)
                self.log.flush()
                self.pending += data
                if b"panic:" in self.pending or b"FAIL" in self.pending:
                    raise AssertionError(self.pending.decode(errors="replace"))
        i = self.pending.index(needle) + len(needle)
        result, self.pending = self.pending[:i], self.pending[i:]
        return result

    def send(self, text):
        self.proc.stdin.write(text.encode())
        self.proc.stdin.flush()

    def login(self, user, password=None):
        self.expect("login: ")
        self.send(user + "\n")
        self.expect("Password: ")
        self.send((password or user) + "\n")
        result = self.expect("$ ")
        assert (password or user).encode() not in result, "password was echoed"

    def command(self, text, expect=None, timeout=30):
        self.send(text + "\n")
        result = self.expect("$ ", timeout)
        if expect:
            assert expect.encode() in result, (text, result)
        return result

    def close(self):
        self.proc.stdin.write(b"\x01x")
        self.proc.stdin.flush()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        self.log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="run full usertests")
    parser.add_argument("--skip-usertests", action="store_true")
    parser.add_argument("--cpus", type=int, default=3)
    args = parser.parse_args()
    subprocess.run(["make", "-j4", "kernel/kernel", "fs.img"], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    logs = ROOT / "lab"
    with tempfile.TemporaryDirectory(prefix="xv6-security-test-") as tmp:
        disk = Path(tmp) / "fs.img"
        shutil.copyfile(ROOT / "fs.img", disk)
        vm = VM(disk, logs / "security-test.log", args.cpus)
        try:
            vm.expect("login: ")
            vm.send("alice\n")
            vm.expect("Password: ")
            vm.send("wrong-password\n")
            result = vm.expect("Login incorrect")
            assert b"wrong-password" not in result
            # Reject a valid password followed by more than the accepted length.
            vm.expect("login: ")
            vm.send("alice\n")
            vm.expect("Password: ")
            vm.send("alice" + "x" * 65 + "\n")
            vm.expect("Login incorrect")
            vm.login("alice")
            vm.command("ls memo.txt", "-rw------- alice users memo.txt")
            vm.command("cat memo.txt", "Alice's private memo.")
            vm.command("cat /shadow", "cannot open")
            vm.command("chmod 640 memo.txt")
            vm.command("ls memo.txt", "-rw-r----- alice users memo.txt")
            vm.command("chown bob memo.txt", "cannot change")
            vm.send("\x04")
            vm.login("bob")
            vm.command("cat /alice/memo.txt", "Alice's private memo.")
            vm.command("echo overwrite > /alice/memo.txt", "open /alice/memo.txt failed")
            vm.send("\x04")
            vm.login("carol")
            vm.command("cat /alice/memo.txt", "cannot open")
            vm.send("\x04")
            vm.login("root")
            vm.command("securitytests", "ALL SECURITY TESTS PASSED", 120)
            print("PASS: login, commands, kernel security tests", flush=True)
            vm.command("chown bob:guests /alice/memo.txt")
            vm.command("chmod 600 /alice/memo.txt")
            vm.command("sync")
            if not args.skip_usertests:
                vm.command("usertests" if args.full else "usertests -q",
                           "ALL TESTS PASSED", 900)
                print("PASS: usertests", flush=True)
        finally:
            vm.close()
        vm = VM(disk, logs / "security-reboot.log", args.cpus)
        try:
            vm.login("root")
            vm.command("ls /alice/memo.txt", "-rw------- bob guests memo.txt")
            vm.send("\x04")
            vm.login("alice")
            vm.command("cat memo.txt", "cannot open")
            print("PASS: ownership and permissions persist across reboot", flush=True)
        finally:
            vm.close()

if __name__ == "__main__":
    main()

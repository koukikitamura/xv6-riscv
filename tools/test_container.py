#!/usr/bin/env python3
"""Boot container tests on a private disk, preserving the QEMU transcript."""
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
    parser.add_argument("--cpus", type=int, default=3)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--skip-usertests", action="store_true")
    args = parser.parse_args()
    subprocess.run(["make", "-j4", "kernel/kernel", "fs.img"], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    logs = ROOT / "lab"
    logs.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xv6-container-test-") as tmp:
        disk = Path(tmp) / "fs.img"
        shutil.copyfile(ROOT / "fs.img", disk)
        vm = VM(disk, logs / f"container-{args.cpus}cpu.log", args.cpus)
        try:
            vm.expect("$ ")
            vm.command("containertests", "ALL CONTAINER TESTS PASSED", 120)
            print("PASS: kernel container tests", flush=True)
            vm.command("echo HOST_ONLY > hostfile")
            launch = "container run --image xv6-shell --cpu 1 --memory 8M --max-procs 8 /sh"
            vm.command(launch)
            vm.command("cat /hostfile", "cannot open")
            vm.command("cat /../../hostfile", "cannot open")
            vm.command("echo PRIVATE > private")
            vm.command("cat private", "PRIVATE")
            # Relative paths can build trees deeper than MAXPATH; cleanup
            # must neither overflow the user stack nor exhaust descriptors.
            for _ in range(20):
                vm.command("/mkdir deep")
                vm.command("cd deep")
            vm.command("/echo nested > leaf")
            vm.command("cd /")
            listing = vm.command("ps", "PID CID STATE NAME")
            assert b"init" not in listing and b"container" not in listing, listing
            vm.send("\x04")
            vm.expect("$ ")
            vm.command("cat hostfile", "HOST_ONLY")
            vm.command(launch)
            vm.command("cat private", "cannot open")
            vm.send("\x04")
            vm.expect("$ ")
            vm.command("container run --image xv6-shell /echo image-ok", "image-ok")
            vm.command("container run --image README /sh", "invalid image")
            vm.command("container run --image xv6-shell --memory 1 /sh", "cannot enter")
            vm.command("container run --image xv6-shell /missing", "cannot execute")
            vm.command("container run --image xv6-shell --cpu 0 /sh", "usage:")
            vm.command("container run --image xv6-shell /echo still-ok", "still-ok")
            print("PASS: image extraction, shell, fresh instances, failure cleanup", flush=True)
            listing = vm.command("ls")
            import re
            assert not re.search(rb"(?:^|\n)c[0-9]+-[0-9]+\s", listing), listing
            vm.command("rm hostfile")
            if not args.skip_usertests:
                vm.command("usertests" if args.full else "usertests -q",
                           "ALL TESTS PASSED", 900)
                print("PASS: usertests", flush=True)
        finally:
            vm.close()

if __name__ == "__main__":
    main()

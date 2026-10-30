#!/usr/bin/env python3

#
# python script that tests xv6 without having to boot it and type to its shell
#
# ./test-xv6.py usertests  (runs usertests)
# ./test-xv6.py -q usertests (runs the quick tests of usertests)
# ./test-xv6.py crash  (runs the crash tests)
# ./test-xv6.py log (runs the log crash test)

import argparse, os, inspect, re, select, signal, socket, struct, subprocess, sys, tempfile, time
from subprocess import run

parser = argparse.ArgumentParser()
parser.add_argument('testrex', help="test name or regular expression")
parser.add_argument("-q", action='store_true', help="usertests quick")
args = parser.parse_args()

class QEMU(object):

    def __init__(self, reset=False):
        if reset:
            self.build_xv6()
            self.reset_fs()
        self.tmp = tempfile.TemporaryDirectory(prefix="xv6-monitor-", dir="/tmp")
        self.monitor_path = self.tmp.name + "/monitor"
        q = ["make", "qemu", "QEMUEXTRA=-monitor unix:" + self.monitor_path +
             ",server=on,wait=off"]
        self.proc = subprocess.Popen(q, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, start_new_session=True)
        self.output = ""
        self.outbytes = bytearray()       
        self.monitor(r'^login: ', timeout=30)
        self.cmd("root\n")
        self.monitor(r'^Password: ', timeout=30)
        self.cmd("root\n")
        self.monitor(r'^\$ ', timeout=30)

    def reset_fs(self):
        try:
            run(["rm", "-f", "fs.img"], check=True)
            run(["make", "fs.img"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")

    def build_xv6(self):
        try:
            run(["make", "kernel/kernel"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")

    def save_output(self):
      try:
        with open("test-xv6.out", "w") as f:
            f.write(self.output)
            f.close()
      except OSError as e:
        print("Provided a bad results path. Error:", e)     
        
    def cmd(self, c):
        if isinstance(c, str):
            c = c.encode('utf-8')
        self.proc.stdin.write(c)
        self.proc.stdin.flush()
        
    def crash(self):
        # Kill make and QEMU together on Linux and macOS.
        os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait()
        self.tmp.cleanup()

    def stop(self):
        if self.proc.poll() is not None:
            return
        self.cmd("\x01x")
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        self.tmp.cleanup()

    def read(self):
        ready, _, _ = select.select([self.proc.stdout], [], [], 1)
        if not ready:
            return
        buf = os.read(self.proc.stdout.fileno(), 4096)
        if not buf:
            self.error()
        self.outbytes.extend(buf)
        self.output = self.outbytes.decode("utf-8", "replace")

    def lines(self):
        return self.output.splitlines()

    def error(self):
        print("FAIL: QEMU stopped or expected output was not found")
        self.save_output()
        self.stop()
        sys.exit(1)

    def match(self, *regexps, exit=True):
        lines = self.lines()
        last = -1
        for i, line in enumerate(lines):
            if any(re.match(r, line) for r in regexps):
                print(line)
                last = i
        if last == -1 and exit:
            self.error()
        l = ""
        if last >= 0:
            l = lines[last]
        return last >= 0, l

    def monitor(self, *regexps, progress="", timeout):
        deadline = time.time() + timeout
        while True:
            time.sleep(1)
            timeleft = deadline - time.time()
            if timeleft < 0:
                self.error()
            self.read()
            ok, _ = self.match(*regexps, exit=False)
            if ok:
                return
            ok, line = self.match(progress, exit=False)
            if ok:
                print(line)

def crash_log():
    q = QEMU(True)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
            monitor.settimeout(5)
            monitor.connect(q.monitor_path)
            def prompt():
                data = b""
                while b"(qemu)" not in data:
                    block = monitor.recv(4096)
                    if not block:
                        raise RuntimeError("QEMU monitor disconnected")
                    data += block
            def command(text):
                monitor.sendall(text.encode() + b"\n")
                prompt()
            prompt()
            q.cmd("logstress f0 f1 f2 f3 f4 f5\n")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                time.sleep(0.005)
                command("stop")
                # Check a quiescent image, not a race with a clearing log header.
                with open("fs.img", "rb", buffering=0) as disk:
                    disk.seek(1024 + 20)  # superblock.logstart
                    start, = struct.unpack("<I", disk.read(4))
                    disk.seek(start * 1024)
                    count, = struct.unpack("<I", disk.read(4))
                if count:
                    q.crash()
                    return
                command("cont")
            raise RuntimeError("no committed log transaction observed")
    finally:
        q.stop()

def recover_log():
    q = QEMU()
    time.sleep(2)
    q.read()
    ok, _ = q.match('^recovering', exit=False)
    if ok:
        q.cmd("ls\n")
        time.sleep(2)
        q.read()
        q.match(r'^-.*\bf5$')
    q.stop()
    return ok

def forphan():
    q = QEMU(True)
    q.cmd("forphan\n")
    time.sleep(5)
    q.read()
    q.match('wait')
    q.crash()
    q.stop()

def dorphan():
    q = QEMU(True)
    q.cmd("dorphan\n")
    time.sleep(5)
    q.read()
    q.match('wait')
    q.crash()
    q.stop()

def recover_orphan():
    q = QEMU()
    time.sleep(2)
    q.read()
    q.match('^ireclaim')
    q.stop()

def test_log():
    print("Test recovery of log")
    for i in range(5):
        crash_log()
        ok = recover_log()
        if ok:
            print("OK")
            return
        print("log attempt ", i+1)
    print("FAIL")
    sys.exit(1)
    
def test_forphan():
    print("Test recovery of an orphaned file")
    forphan()
    recover_orphan()
    print("OK")

def test_dorphan():
    print("Test recovery of an orphaned file")
    dorphan()
    recover_orphan()
    print("OK")

def test_crash():
    test_log()
    test_forphan()
    test_dorphan()

def test_usertests(test=""):
    timeout = 600
    opt = ""
    if args.q:
        opt = " -q"
        timeout = 300
    elif test != "":
        opt += " " + test
    q = QEMU(True)
    q.cmd("usertests" + opt + "\n")
    q.monitor('^ALL TESTS PASSED', progress='test', timeout=timeout)
    q.stop()

def main():
    print(args)
    rex = r'%s' % args.testrex
    funcs = [(obj,name) for name,obj in inspect.getmembers(sys.modules[__name__]) 
                     if (inspect.isfunction(obj) and 
                         name.startswith('test'))]
    none = True
    for (f,n) in funcs:
        if re.search(rex, n):
            none = False
            f()
    if none:
        test_usertests(test=args.testrex)

main()

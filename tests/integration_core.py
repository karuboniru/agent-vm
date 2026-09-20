#!/usr/bin/env python3
"""Real-VM acceptance tests. Run outside a tool sandbox with /dev/kvm access."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import struct
import tempfile
import termios
import time


parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "build/agent-vm")
args = parser.parse_args()
binary = args.binary.resolve()
checks = 0


def check(condition, description):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(description)
    print("PASS", description, flush=True)


with tempfile.TemporaryDirectory(prefix="agent-vm-core-test-") as directory:
    base = Path(directory)
    home = base / "home"
    work = home / "project"
    work.mkdir(parents=True)
    (home / ".ssh").mkdir()
    (home / ".ssh/key").write_text("fixture-secret")
    (home / "public").write_text("fixture-public")
    env = dict(os.environ, HOME=str(home), AVM_TEST_PRIVATE="not-inherited", AVM_TEST_INHERIT="inherited-value")
    env.pop("SSH_AUTH_SOCK", None)
    common = [str(binary), "run", "--no-config", "--cpus", "1", "--memory", "512"]

    def run(command, options=(), expected=0, stdin=None, timeout=20):
        p = subprocess.Popen(common + list(options) + ["--"] + list(command), cwd=work, env=env,
                             stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, err = p.communicate()
            raise AssertionError(f"VM timed out: {command!r}\nstdout={out!r}\nstderr={err!r}")
        if p.returncode != expected:
            raise AssertionError(f"exit {p.returncode}, expected {expected}: {command!r}\nstdout={out!r}\nstderr={err!r}")
        return out.decode(), err.decode()

    code = """import os,json,pathlib
p=pathlib.Path('created');p.write_text('persistent')
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'cwd':os.getcwd(),'owner':p.stat().st_uid,'home':os.environ['HOME'],'private':os.getenv('AVM_TEST_PRIVATE'),'inherited':os.getenv('AVM_TEST_INHERIT'),'value':os.getenv('COMPLEX')}))
"""
    complex_value = "spaces 'quotes' \"double\"\nnewline=$literal"
    out, _ = run(["python3", "-c", code], ["-e", "AVM_TEST_INHERIT", "-e", "COMPLEX=" + complex_value])
    result = json.loads(out)
    check(result["uid"] == os.getuid() and result["gid"] == os.getgid(), "guest numeric UID/GID")
    check(result["cwd"] == str(work) and result["owner"] == os.getuid(), "CWD and guest file ownership")
    check((work / "created").read_text() == "persistent" and (work / "created").stat().st_uid == os.getuid(), "host sees persistent shared writes with caller UID")
    check(result["private"] is None and result["inherited"] == "inherited-value", "environment allowlist and explicit inheritance")
    check(result["value"] == complex_value, "literal environment quotes and newlines")

    out, _ = run(["python3", "-c", """import os,json,pathlib
mounts={}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
 left,right=line.split(' - ');mounts.setdefault(left.split()[4],right.split()[:2])
paths=['/','/tmp','/var/tmp','/run',os.environ['HOME'],'/usr',os.getcwd()]
print(json.dumps({p:mounts[p] for p in paths}))
assert not pathlib.Path('/.oldroot').exists()
assert not pathlib.Path('/.agent-vm/objects').exists()
assert not pathlib.Path('/.agent-vm/bootstrap').exists()
"""])
    filesystems = json.loads(out)
    check(all(filesystems[p][0] == "tmpfs" for p in ["/", "/tmp", "/var/tmp", "/run", str(home)]),
          "root and private writable directories use guest-native tmpfs")
    check(all(filesystems[p] == ["virtiofs", "/.agent-vm/exports"] for p in ["/usr", str(work)]),
          "shared objects use one path-tagged virtiofs catalog without an IRQ per mount")
    out, _ = run(["python3", "-c", """import errno,pathlib
for p in ['/tmp/full','/var/tmp/full']:
 try: pathlib.Path(p).write_bytes(b'x'*(2*1024*1024))
 except OSError as e: assert e.errno==errno.ENOSPC,e
 else: raise AssertionError('tmpfs capacity limit missing')
print('limits-ok')
"""], ["--tmp-size", "1"])
    check(out.strip() == "limits-ok", "guest tmpfs preserves per-filesystem capacity limits")

    single_file = base / "single-file"
    single_file.write_text("original")
    long_target = "/long-" + "x" * 80 + "/file"
    out, _ = run(["python3", "-c", """import errno,pathlib,sys
ro=pathlib.Path('/single-ro');rw=pathlib.Path(sys.argv[1])
assert ro.read_text()=='original'
try: ro.write_text('forbidden')
except OSError as e: assert e.errno==errno.EROFS,e
else: raise AssertionError('ro file writable')
rw.write_text('updated')
assert ro.read_text()=='updated'
print('files-ok')
""", long_target], ["--mount", f"src={single_file},dst=/single-ro,ro",
                    "--mount", f"src={single_file},dst={long_target},rw"])
    check(out.strip() == "files-ok" and single_file.read_text() == "updated",
          "single-file objects preserve independent ro/rw modes and long target paths")

    out, _ = run(["python3", "-c", """import pathlib
assert not pathlib.Path('/single-hidden').read_bytes()
assert not list(pathlib.Path('/tmp/hidden').iterdir())
print('private-masks-ok')
"""], ["--mount", f"src={single_file},dst=/single-hidden,rw",
        "--mask-target", "/single-hidden", "--mask-target", "/tmp/hidden"])
    check(out.strip() == "private-masks-ok" and single_file.read_text() == "updated",
          "whole-file and private-tmpfs target masks survive guest assembly")

    special = ["", "with spaces", "one'two", 'one"two', "line1\nline2", "$(not-a-command)"]
    out, _ = run(["python3", "-c", "import json,sys;print(json.dumps(sys.argv[1:]))"] + special)
    check(json.loads(out) == special, "argv exact round trip without shell interpretation")

    out, _ = run(["python3", "-c", "import os;print(os.path.exists(os.environ['HOME']+'/public'))"])
    check(out.strip() == "False", "ephemeral home does not expose host home")
    out, _ = run(["python3", "-c", "import os,pathlib,json;h=pathlib.Path(os.environ['HOME']);print(json.dumps([list((h/'.ssh').iterdir()),list(pathlib.Path('/alias/.ssh').iterdir()),(h/'public').read_text()]))"],
                 ["--home", "shared", "--mount", f"src={home},dst=/alias,ro", "--mask", str(home / ".ssh")])
    check(json.loads(out) == [[], [], "fixture-public"], "source mask covers shared home and its second alias")
    check((home / ".ssh/key").read_text() == "fixture-secret", "mask leaves host secret unchanged")
    for options in (["--home", "shared", "--mask", str(home / "missing")],
                    ["--mask", str(home / ".ssh"), "--mount", f"src={home / '.ssh'},dst=/keys,ro"],
                    ["--mount", f"src={work},dst=/etc,ro"]):
        _, error = run(["true"], options, expected=125)
        check(bool(error), "invalid mask/mount combination fails closed")

    out, _ = run(["python3", "-c", "import os,errno\ntry: open('new-file','w')\nexcept OSError as e: print(e.errno)"], ["--cwd-mode", "ro"])
    check(out.strip() == str(errno.EROFS) and not (work / "new-file").exists(), "readonly CWD enforced by host mount")
    out, _ = run(["python3", "-c", "import os,json\nr=[]\nfor p in ['/new-root-file','/etc/new-file','/usr/new-file']:\n try: open(p,'w');r.append(0)\n except OSError as e:r.append(e.errno)\nprint(json.dumps(r))"])
    check(all(e in (errno.EROFS, errno.EACCES) for e in json.loads(out)), "root, /etc and /usr reject writes")

    # Default rw CWD can be an exception within a ro home, with further
    # explicit ro/rw exceptions below it. Supply mounts in reverse depth order.
    locked = work / "locked"
    writable = locked / "writable"
    writable.mkdir(parents=True)
    out, _ = run(["python3", "-c", """import errno,os,pathlib
h=pathlib.Path(os.environ['HOME'])
for p in [h/'denied',pathlib.Path('locked/denied')]:
 try: p.write_text('unexpected')
 except OSError as e: assert e.errno==errno.EROFS,(p,e)
 else: raise AssertionError('read-only parent writable: '+str(p))
pathlib.Path('nested-output').write_text('cwd')
pathlib.Path('locked/writable/output').write_text('leaf')
print('nested-modes-ok')
"""], ["--mount", f"src={writable},dst={writable},rw",
        "--mount", f"src={locked},dst={locked},ro",
        "--mount", f"src={home},dst={home},ro"])
    check(out.strip() == "nested-modes-ok" and (work / "nested-output").read_text() == "cwd" and
          (writable / "output").read_text() == "leaf" and not (home / "denied").exists() and
          not (locked / "denied").exists(), "nested ro/rw mounts preserve each explicit mode in guest and host")

    out, _ = run(["python3", "-c", """import pathlib,socket,json
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
c=socket.socket();c.settimeout(2);c.connect(s.getsockname());a,_=s.accept();c.sendall(b'local')
print(json.dumps({'interfaces':[p.name for p in pathlib.Path('/sys/class/net').iterdir()],
 'routes':pathlib.Path('/proc/net/route').read_text().splitlines()[1:],
 'tsi':'tsi_hijack' in pathlib.Path('/proc/cmdline').read_text().split(),
 'loopback':a.recv(5).decode()}))
"""])
    networking = json.loads(out)
    check("eth0" not in networking["interfaces"] and not networking["routes"] and not networking["tsi"],
          "network none has no external NIC, routes or TSI hijack")
    check(networking["loopback"] == "local", "network none preserves guest-local loopback")
    run(["sh", "-c", "exit 37"], expected=37)
    check(True, "workload exit status 37 preserved")
    run(["agent-vm-no-such-command"], expected=127)
    check(True, "missing command returns 127")
    out, err = run(["cat"], stdin=b"pipe-input\n")
    check(out == "pipe-input\n" and not err, "stdin pipe and EOF reach the guest")
    out, err = run(["sh", "-c", "printf 'output'; printf 'error' >&2"])
    check(out == "output" and err == "error", "stdout and stderr stay separate")

    # A readiness message comes from the workload, after control is available.
    p = subprocess.Popen(common + ["--", "python3", "-c", "import time;print('ready',flush=True);time.sleep(60)"],
                         cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        check(bool(select.select([p.stdout], [], [], 15)[0]), "signal test workload starts")
        check(p.stdout.readline().strip() == b"ready", "signal test readiness")
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        check(p.returncode == 143, f"host SIGTERM forwarded to guest (status {p.returncode}, stderr {err!r})")
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()

    p = subprocess.Popen(common + ["--network", "passt", "--", "python3", "-c", "import time;print('ready',flush=True);time.sleep(60)"],
                         cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        if not select.select([p.stdout], [], [], 15)[0] or p.stdout.readline().strip() != b"ready":
            raise AssertionError("process-group signal test did not start")
        os.killpg(p.pid, signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        check(p.returncode == 143, f"process-group SIGTERM preserves graceful guest shutdown with passt (status {p.returncode}, stderr {err!r})")
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()

    # Validate console operation and parent terminal restoration through a PTY.
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    terminal_program = """import os,signal,time
assert os.isatty(0)
def changed(*args):
 s=os.get_terminal_size(0)
 if s.lines==40 and s.columns==100:
  print('RESIZE-OK',flush=True)
  raise SystemExit(0)
signal.signal(signal.SIGWINCH,changed)
print('PTY-OK',flush=True)
while True: time.sleep(1)
"""
    p = subprocess.Popen(common + ["--", "python3", "-c", terminal_program], cwd=work, env=env,
                         stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    try:
        output = bytearray()
        resized = False
        until = time.monotonic() + 15
        while p.poll() is None and time.monotonic() < until:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output += os.read(master, 65536)
                    if b"PTY-OK" in output and not resized:
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
                        p.send_signal(signal.SIGWINCH)
                        resized = True
                except OSError:
                    break
        p.wait(timeout=3)
        while select.select([master], [], [], 0)[0]:
            output += os.read(master, 65536)
        check(p.returncode == 0 and b"PTY-OK" in output, f"interactive PTY console ({bytes(output)!r})")
        check(b"RESIZE-OK" in output, "window resize reaches guest foreground workload")
        check(termios.tcgetattr(slave) == before, "host terminal settings restored")
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        os.close(master)
        os.close(slave)

print(f"{checks} core VM integration checks passed")

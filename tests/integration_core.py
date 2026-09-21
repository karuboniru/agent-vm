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

    def run(command, options=(), expected=0, stdin=None, timeout=20, config=None):
        invocation = common if config is None else [arg for arg in common if arg != "--no-config"] + ["--config", str(config)]
        p = subprocess.Popen(invocation + list(options) + ["--"] + list(command), cwd=work, env=env,
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

    run(["/usr/bin/python3", "-c", """
import os
for path in ('/.agent-vm/ipc', '/ipc'):
    assert not os.path.lexists(path), 'host IPC exposed: ' + path
assert '/.agent-vm/ipc' not in open('/proc/self/mountinfo').read()
"""])
    check(True, "host IPC absent from guest filesystem and mount table")

    run(["python3", "-c", """from pathlib import Path
cmdline = Path('/proc/cmdline').read_text().split(' -- ', 1)[0]
assert 'oops=panic' in cmdline and 'panic=-1' in cmdline, cmdline
assert Path('/proc/sys/kernel/panic_on_oops').read_text().strip() == '1'
assert Path('/proc/sys/kernel/panic').read_text().strip() == '-1'
"""])
    check(True, "guest kernel enables panic on Oops and immediate reset on panic")

    mount_targets = ["/run/media/test-volume/project", "/usr/share/misc", "/etc/custom"]
    mount_options = []
    for target in mount_targets:
        mount_options += ["--mount", f"src={home},dst={target},rw"]
    run(["/usr/bin/python3", "-c", """import pathlib, sys
for target in sys.argv[1:]:
 p = pathlib.Path(target)
 assert (p / 'public').read_text() == 'fixture-public'
 (p / 'mounted-write').write_text('shared')
""", *mount_targets], mount_options + ["--workdir", mount_targets[0]])
    check((home / "mounted-write").read_text() == "shared", "writable binds beneath runtime and system directories")

    run(["/usr/bin/python3", "-c", """import pathlib
for target in ('/usr/share/misc', '/etc/custom'):
 p = pathlib.Path(target)
 (p / 'private').write_text('temporary')
 assert (p / 'child/public').read_text() == 'fixture-public'
"""], ["--tmpfs", "target=/usr/share/misc", "--tmpfs", "target=/etc/custom",
       "--mount", f"src={home},dst=/usr/share/misc/child,ro",
       "--mount", f"src={home},dst=/etc/custom/child,ro"])
    check(not (home / "private").exists(), "system subtree tmpfs permits private files and explicit bind children")

    ca_sources = [Path(p) for p in ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                                  "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem")]
    ca_source = next((p for p in ca_sources if p.is_file()), None)
    if ca_source is not None:
        import hashlib
        digest = hashlib.sha256(ca_source.read_bytes()).hexdigest()
        run(["python3", "-c", """import hashlib, pathlib, ssl, sys
for path in ('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
             '/etc/pki/tls/certs/ca-bundle.crt', '/etc/pki/tls/cert.pem',
             '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem'):
 assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == sys.argv[1], path
 context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
 context.load_verify_locations(cafile=path)
 assert context.cert_store_stats()['x509_ca'] > 0, path
""", digest], ["--network", "none"])
        check(True, "host CA bundle loads at all guest TLS trust paths")

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

    custom_tmpfs = ["--tmpfs", "target=/cache/nested,mode=0750",
                    "--tmpfs", "target=/run/custom,mode=0770",
                    "--tmpfs", "target=/cache",
                    "--tmpfs", "target=/root-owned,uid=0,gid=0,mode=0750",
                    "--tmpfs", f"target=/foreign-owned,uid={os.getuid() + 1},gid={os.getgid() + 1},mode=0700",
                    "--tmp-size", "1", "--workdir", "/cache"]
    out, _ = run(["python3", "-c", """import errno,json,os,pathlib,stat
paths=['/cache','/cache/nested','/run/custom','/root-owned','/foreign-owned']
mounts={}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
 left,right=line.split(' - ');mounts[left.split()[4]]=right.split()[0]
assert all(mounts[p]=='tmpfs' for p in paths),mounts
assert os.getcwd()=='/cache'
assert sorted(p.name for p in pathlib.Path('/cache').iterdir())==['nested']
for p in ['/cache/payload','/cache/nested/payload','/run/custom/payload']:
 pathlib.Path(p).write_bytes(b'x'*(768*1024))
 try: pathlib.Path(p+'-overflow').write_bytes(b'x'*(512*1024))
 except OSError as e: assert e.errno==errno.ENOSPC,e
 else: raise AssertionError('custom tmpfs capacity limit missing: '+p)
print(json.dumps({p:[(s:=os.stat(p)).st_uid,s.st_gid,stat.S_IMODE(s.st_mode)] for p in paths}))
"""], custom_tmpfs)
    metadata = json.loads(out)
    check(metadata == {"/cache": [os.getuid(), os.getgid(), 0o700],
                       "/cache/nested": [os.getuid(), os.getgid(), 0o750],
                       "/run/custom": [os.getuid(), os.getgid(), 0o770],
                       "/root-owned": [0, 0, 0o750],
                       "/foreign-owned": [os.getuid() + 1, os.getgid() + 1, 0o700]},
          "custom tmpfs applies caller defaults and explicit numeric ownership and modes")
    check(True, "custom tmpfs supports nested mounts in reverse order, workdir, and independent capacity limits")

    config = base / "tmpfs.toml"
    config.write_text("""version = 1
[[tmpfs]]
target = "/cache/nested"
mode = 0o750
[[tmpfs]]
target = "/cache"
[[tmpfs]]
target = "/configured"
uid = 0
gid = 0
mode = 0o755
""")
    out, _ = run(["python3", "-c", """import os,pathlib,stat
assert sorted(p.name for p in pathlib.Path('/cache').iterdir())==['nested']
assert not list(pathlib.Path('/cache/nested').iterdir())
assert stat.S_IMODE(os.stat('/cache/nested').st_mode)==0o750
info=os.stat('/configured')
assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,0,0o755)
info=os.stat('/cli-added')
assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(os.getuid(),os.getgid(),0o700)
pathlib.Path('/cli-added/output').write_text('private')
print('configured-tmpfs-ok')
"""], ["--tmpfs", "dst=/cli-added"], config=config)
    check(out.strip() == "configured-tmpfs-ok", "TOML tmpfs and CLI additions combine, and prior guest writes do not persist")

    tmpfs_share = base / "tmpfs-share"
    covered = tmpfs_share / "cache"
    covered.mkdir(parents=True)
    tmpfs_share.chmod(0o751)
    covered.chmod(0o750)
    host_file = covered / "host-only"
    host_file.write_text("host-data")
    host_file.chmod(0o640)
    preserved = {p: p.stat() for p in (tmpfs_share, covered, host_file)}
    out, _ = run(["python3", "-c", """import errno,os,pathlib,stat
root=pathlib.Path('/srv/readonly/cache')
assert not list(root.iterdir())
assert not (root/'host-only').exists()
assert pathlib.Path('/srv/alias/cache/host-only').read_text()=='host-data'
info=root.stat()
assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(os.getuid(),os.getgid(),0o700)
(root/'guest-only').write_text('private-data')
try: pathlib.Path('/srv/readonly/denied').write_text('forbidden')
except OSError as e: assert e.errno==errno.EROFS,e
else: raise AssertionError('read-only tmpfs parent writable')
print('shared-tmpfs-ok')
"""], ["--mount", f"src={tmpfs_share},dst=/srv/readonly,ro",
        "--mount", f"src={tmpfs_share},dst=/srv/alias,ro",
        "--tmpfs", "target=/srv/readonly/cache"])
    check(out.strip() == "shared-tmpfs-ok", "custom tmpfs hides a read-only shared subtree while preserving its other alias")
    check(host_file.read_text() == "host-data" and sorted(p.name for p in covered.iterdir()) == ["host-only"] and
          not (tmpfs_share / "denied").exists(), "custom tmpfs writes do not reach the covered host directory")
    for path, before in preserved.items():
        after = path.stat()
        check((after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) ==
              (before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns, before.st_ctime_ns),
              f"custom tmpfs preserves covered host metadata: {path.name}")

    gnupg = home / ".gnupg"
    gnupg.mkdir(mode=0o700)
    keyring = gnupg / "pubring.kbx"
    keyring.write_bytes(b"fixture-public-keyring")
    keyring.chmod(0o600)
    (gnupg / "host-private").write_bytes(b"fixture-hidden-file")
    gnupg_before = {p: p.stat() for p in (gnupg, keyring, gnupg / "host-private")}
    gnupg_config = base / "gnupg.toml"
    gnupg_config.write_text("""version = 1
[[tmpfs]]
target = "~/.gnupg"
mode = 0o700
[[mounts]]
source = "~/.gnupg/pubring.kbx"
target = "~/.gnupg/pubring.kbx"
mode = "ro"
""")
    for home_mode in ("ephemeral", "shared"):
        out, _ = run(["python3", "-c", """import errno,os,pathlib,socket,stat
root=pathlib.Path(os.environ['HOME'])/'.gnupg'
assert os.getcwd()==str(root.parent/'project')
assert sorted(p.name for p in root.iterdir())==['pubring.kbx']
mounts={}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
 left,right=line.split(' - ');mounts[left.split()[4]]=right.split()[0]
assert mounts[str(root)]=='tmpfs'
assert mounts[str(root/'pubring.kbx')]=='virtiofs'
info=root.stat()
assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(os.getuid(),os.getgid(),0o700)
assert (root/'pubring.kbx').read_bytes()==b'fixture-public-keyring'
try: (root/'pubring.kbx').write_bytes(b'forbidden')
except OSError as e: assert e.errno==errno.EROFS,e
else: raise AssertionError('public keyring bind is writable')
(root/'trustdb.gpg').write_bytes(b'private-runtime-state')
(root/'private-keys-v1.d').mkdir()
(root/'private-keys-v1.d/runtime').write_bytes(b'private-runtime-file')
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as endpoint:
 endpoint.bind(str(root/'S.gpg-agent'))
 endpoint.listen()
 assert stat.S_ISSOCK((root/'S.gpg-agent').stat().st_mode)
print('gnupg-tmpfs-ok')
"""], ["--home", home_mode], config=gnupg_config)
        check(out.strip() == "gnupg-tmpfs-ok", f"private GnuPG tmpfs supports a read-only keyring bind with {home_mode} home")
    check(sorted(p.name for p in gnupg.iterdir()) == ["host-private", "pubring.kbx"] and
          keyring.read_bytes() == b"fixture-public-keyring" and
          (gnupg / "host-private").read_bytes() == b"fixture-hidden-file" and
          all((after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) ==
              (before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns, before.st_ctime_ns)
              for path, before in gnupg_before.items() for after in [path.stat()]),
          "GnuPG runtime files, socket and directories do not persist or alter the host keyring")

    layered_parent = base / "layered-parent"
    layered_cache = layered_parent / "cache"
    layered_cache.mkdir(parents=True)
    (layered_cache / "covered-host").write_text("covered-data")
    layered_output = base / "layered-output"
    layered_scratch = layered_output / "scratch"
    layered_scratch.mkdir(parents=True)
    (layered_output / "shared-original").write_text("shared-data")
    (layered_scratch / "deep-host").write_text("deep-data")
    layered_before = {p: p.stat() for p in (layered_parent, layered_cache, layered_cache / "covered-host",
                                          layered_output / "shared-original", layered_scratch, layered_scratch / "deep-host")}
    output_before = layered_output.stat()
    # Each layer changes the effective parent filesystem for the next one.
    layers = [("--mount", f"src={layered_parent},dst=/data,ro"),
              ("--tmpfs", "target=/data/cache"),
              ("--mount", f"src={layered_output},dst=/data/cache/output,rw"),
              ("--tmpfs", "target=/data/cache/output/scratch")]
    for order, ordered_layers in (("forward", layers), ("reverse", list(reversed(layers)))):
        out, _ = run(["python3", "-c", """import errno,os,pathlib,stat,sys
cache=pathlib.Path('/data/cache');output=cache/'output';scratch=output/'scratch'
mounts={}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
 left,right=line.split(' - ');mounts[left.split()[4]]=right.split()[0]
assert {p:mounts[p] for p in ['/data',str(cache),str(output),str(scratch)]}=={
 '/data':'virtiofs',str(cache):'tmpfs',str(output):'virtiofs',str(scratch):'tmpfs'}
for p in (cache,scratch):
 info=p.stat()
 assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(os.getuid(),os.getgid(),0o700)
assert sorted(p.name for p in cache.iterdir())==['output']
assert not list(scratch.iterdir())
assert (output/'shared-original').read_text()=='shared-data'
try: pathlib.Path('/data/denied').write_text('forbidden')
except OSError as e: assert e.errno==errno.EROFS,e
else: raise AssertionError('outer shared parent writable')
(cache/'guest-only').write_text('private-data')
(scratch/'guest-only').write_text('private-data')
(output/('approved-'+sys.argv[1])).write_text('authorized-'+sys.argv[1])
print('alternating-layers-ok')
""", order], [item for layer in ordered_layers for item in layer])
        check(out.strip() == "alternating-layers-ok", f"alternating read-only bind, tmpfs, writable bind and tmpfs layers in {order} order")
    output_after = layered_output.stat()
    check(sorted(p.name for p in layered_parent.iterdir()) == ["cache"] and
          sorted(p.name for p in layered_cache.iterdir()) == ["covered-host"] and
          sorted(p.name for p in layered_scratch.iterdir()) == ["deep-host"] and
          sorted(p.name for p in layered_output.iterdir()) == ["approved-forward", "approved-reverse", "scratch", "shared-original"] and
          (layered_cache / "covered-host").read_text() == "covered-data" and
          (layered_output / "shared-original").read_text() == "shared-data" and
          (layered_scratch / "deep-host").read_text() == "deep-data" and
          all((layered_output / ("approved-" + order)).read_text() == "authorized-" + order for order in ("forward", "reverse")) and
          (output_after.st_ino, output_after.st_uid, output_after.st_gid, output_after.st_mode) ==
          (output_before.st_ino, output_before.st_uid, output_before.st_gid, output_before.st_mode) and
          all((after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) ==
              (before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns, before.st_ctime_ns)
              for path, before in layered_before.items() for after in [path.stat()]),
          "alternating layers persist only explicit writable-child writes and preserve covered host paths")

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

    etc_source = base / "etc-source"
    etc_source.mkdir()
    (etc_source / "machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    (etc_source / "hostname").write_text("custom-hostname\n")
    (etc_source / "writable").write_text("before")
    etc_config = base / "etc.toml"
    etc_config.write_text(f"""[[mounts]]
source = "{etc_source / 'machine-id'}"
target = "/etc/machine-id"
mode = "ro"
[[mounts]]
source = "{etc_source / 'hostname'}"
target = "/etc/hostname"
mode = "ro"
[[mounts]]
source = "{etc_source / 'writable'}"
target = "/etc/custom/writable"
mode = "rw"
[[mounts]]
source = "{etc_source}"
target = "/etc/custom"
mode = "ro"
""")
    out, _ = run(["python3", "-c", """
from pathlib import Path
import errno
assert Path('/etc/machine-id').read_text() == '0123456789abcdef0123456789abcdef\\n'
assert Path('/etc/hostname').read_text() == 'custom-hostname\\n'
assert Path('/etc/custom/machine-id').read_text() == Path('/etc/machine-id').read_text()
for p in ['/etc/machine-id', '/etc/hostname', '/etc/custom/machine-id']:
    try: open(p, 'w')
    except OSError as e: assert e.errno in (errno.EROFS, errno.EACCES), e
    else: raise AssertionError(p + ' is writable')
Path('/etc/custom/writable').write_text('after')
assert Path('/etc/resolv.conf').exists()
print('etc-binds-ok')
"""], config=etc_config)
    check(out.strip() == "etc-binds-ok" and (etc_source / "writable").read_text() == "after",
          "TOML etc binds support new files, generated-file overrides, directories and nested ro/rw modes")

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

    child_source = base / "new-child"
    child_source.mkdir()
    (child_source / "payload").write_text("mounted")
    out, _ = run(["python3", "-c", """import pathlib
assert pathlib.Path('/created/deep/child/payload').read_text() == 'mounted'
assert pathlib.Path('/created/deep/file').read_text() == 'mounted'
pathlib.Path('/created/cache/output').write_text('temporary')
"""], ["--mount", f"src={child_source},dst=/created/deep/child,ro",
        "--mount", f"src={child_source}/payload,dst=/created/deep/file,ro",
        "--tmpfs", "target=/created/cache",
        "--mount", f"src={work},dst=/created,rw"])
    check((work / "deep/child").is_dir() and (work / "deep/file").is_file() and
          (work / "cache").is_dir() and not (work / "cache/output").exists(),
          "writable parents create directory, file and tmpfs mountpoints before guest mounts")

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

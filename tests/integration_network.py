#!/usr/bin/env python3
"""Real-VM passt and Unix socket tests using disposable local echo services.

Run outside a sandbox that denies KVM, namespaces, or socket binding:
    python3 tests/integration_network.py --binary /absolute/path/to/agent-vm
Each case has a 25-second workload deadline plus bounded process cleanup.
No real SSH agent, host home, public service, or external network is used.
"""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time


EOF_MARKER = b"<EOF>"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def receive_all(connection: socket.socket) -> bytes:
    output = bytearray()
    while data := connection.recv(65536):
        output.extend(data)
    return bytes(output)


class EchoService:
    """Local TCP/Unix stream or UDP endpoint, never consulting host credentials."""

    def __init__(self, family: int, kind: int, address: object, marker: bytes = EOF_MARKER):
        self.kind = kind
        self.marker = marker
        self.listener = socket.socket(family, kind)
        self.listener.bind(address)
        self.address = self.listener.getsockname()
        self.listener.settimeout(0.1)
        if kind == socket.SOCK_STREAM:
            self.listener.listen(32)
        self.stopping = threading.Event()
        self.connections: list[socket.socket] = []
        self.workers: list[threading.Thread] = []
        self.errors: list[BaseException] = []
        self.completed: list[tuple[int, bool]] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _stream(self, connection: socket.socket) -> None:
        received = 0
        marker_sent = False
        try:
            with connection:
                connection.settimeout(20)
                while data := connection.recv(65536):
                    received += len(data)
                    connection.sendall(data)
                connection.sendall(self.marker)
                marker_sent = True
                connection.shutdown(socket.SHUT_WR)
        except OSError as error:
            if not self.stopping.is_set():
                self.errors.append(error)
        finally:
            self.completed.append((received, marker_sent))

    def _serve(self) -> None:
        while not self.stopping.is_set():
            try:
                if self.kind == socket.SOCK_DGRAM:
                    data, peer = self.listener.recvfrom(65535)
                    self.listener.sendto(data, peer)
                else:
                    connection, _ = self.listener.accept()
                    self.connections.append(connection)
                    worker = threading.Thread(target=self._stream, args=(connection,), daemon=True)
                    self.workers.append(worker)
                    worker.start()
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stopping.is_set():
                    self.errors.append(error)
                break

    def __enter__(self) -> "EchoService":
        return self

    def __exit__(self, *_: object) -> None:
        self.stopping.set()
        self.listener.close()
        for connection in self.connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        self.thread.join(0.5)
        for worker in self.workers:
            worker.join(0.1)


class VM:
    def __init__(self, binary: Path, case: Path, source: str, options: list[str],
                 arguments: list[str] | None = None, extra_environment: dict[str, str] | None = None):
        self.case = case
        self.work = case / "work"
        self.work.mkdir()
        home = case / "home"
        home.mkdir(mode=0o700)
        (self.work / "workload.py").write_text(textwrap.dedent(source), encoding="utf-8")
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}
        if extra_environment:
            environment.update(extra_environment)
        command = [str(binary), "run", "--no-config", "--cpus", "1", "--memory", "512", *options,
                   "--", "/usr/bin/python3", "-u", "workload.py", *(arguments or [])]
        self.stdout = (case / "stdout.log").open("wb")
        self.stderr = (case / "stderr.log").open("wb")
        self.deadline = time.monotonic() + 25
        self.process = subprocess.Popen(command, cwd=self.work, env=environment,
                                        stdin=subprocess.DEVNULL, stdout=self.stdout,
                                        stderr=self.stderr, start_new_session=True)

    def wait_file(self, name: str) -> Path:
        path = self.work / name
        while time.monotonic() < self.deadline:
            if path.is_file():
                return path
            require(self.process.poll() is None, f"VM exited before creating {name}: status {self.process.returncode}")
            time.sleep(0.02)
        raise TimeoutError(f"VM did not create {name} within its deadline")

    def finish(self, expected_output: str) -> None:
        remaining = max(0.01, self.deadline - time.monotonic())
        code = self.process.wait(timeout=remaining)
        require(code == 0, f"VM returned status {code}")
        self.stdout.flush()
        output = (self.case / "stdout.log").read_text(encoding="utf-8", errors="replace")
        require(expected_output in output, f"guest success marker missing: {expected_output}")

    def operation_timeout(self, maximum: float = 4) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("VM case exceeded its deadline")
        return min(maximum, remaining)

    def close(self) -> None:
        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)
        self.stdout.close()
        self.stderr.close()

    def __enter__(self) -> "VM":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


OUTBOUND_GUEST = r"""
    import os, socket, sys
    routes = open('/proc/net/route', encoding='ascii').read().splitlines()[1:]
    gateway = None
    for row in routes:
        fields = row.split()
        if fields[1] == '00000000' and int(fields[3], 16) & 2:
            gateway = socket.inet_ntoa(int(fields[2], 16).to_bytes(4, sys.byteorder))
            break
    assert gateway, 'no guest default gateway'
    assert os.getuid() == int(sys.argv[3])
    payload = bytes(range(256)) * 127
    with socket.create_connection((gateway, int(sys.argv[1])), timeout=4) as peer:
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while data := peer.recv(65536):
            response.extend(data)
        assert response == payload + b'<EOF>', 'host TCP echo mismatch'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(4)
        peer.sendto(payload[:1200], (gateway, int(sys.argv[2])))
        assert peer.recv(2000) == payload[:1200], 'host UDP echo mismatch'
    print('OUTBOUND_OK gateway=' + gateway, flush=True)
"""


def test_outbound(binary: Path, case: Path) -> None:
    with EchoService(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0)) as tcp, \
            EchoService(socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0)) as udp:
        with VM(binary, case, OUTBOUND_GUEST, ["--network", "passt"],
                [str(tcp.address[1]), str(udp.address[1]), str(os.getuid())]) as vm:
            vm.finish("OUTBOUND_OK")
        require(not tcp.errors and not udp.errors, f"host echo service errors: {tcp.errors + udp.errors}")


OUTBOUND6_GUEST = r"""
    import socket, sys, time
    deadline = time.monotonic() + 10
    while True:
        addresses = [row.split() for row in open('/proc/net/if_inet6')]
        ready = any(row[3] == '00' and not int(row[4], 16) & 0x48 for row in addresses)
        routes = [row.split() for row in open('/proc/net/ipv6_route')]
        route = next((row for row in routes if row[0] == '0' * 32 and row[1] == '00'
                      and row[4] != '0' * 32), None)
        if ready and route:
            break
        assert time.monotonic() < deadline, 'IPv6 address/default route not ready'
        time.sleep(0.1)
    gateway = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(route[4]))
    scope = socket.if_nametoindex(route[-1])
    payload = bytes(range(256)) * 127
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as peer:
        peer.settimeout(4)
        peer.connect((gateway, int(sys.argv[1]), 0, scope))
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while data := peer.recv(65536):
            response.extend(data)
        assert response == payload + b'<EOF>', 'IPv6 TCP echo mismatch'
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
        peer.settimeout(4)
        peer.sendto(payload[:1200], (gateway, int(sys.argv[2]), 0, scope))
        assert peer.recv(2000) == payload[:1200], 'IPv6 UDP echo mismatch'
    print('OUTBOUND6_OK', flush=True)
"""


def test_outbound6(binary: Path, case: Path) -> None:
    # Automatic passt IPv6 configuration requires a host IPv6 default route.
    routes = Path('/proc/net/ipv6_route')
    if not routes.exists() or not any(
            row[0] == '0' * 32 and row[1] == '00' and int(row[8], 16) & 1
            for row in (line.split() for line in routes.read_text().splitlines())):
        print('SKIP IPv6 echo: host has no IPv6 default route', flush=True)
        return
    with EchoService(socket.AF_INET6, socket.SOCK_STREAM, ("::1", 0)) as tcp, \
            EchoService(socket.AF_INET6, socket.SOCK_DGRAM, ("::1", 0)) as udp:
        with VM(binary, case, OUTBOUND6_GUEST, ["--network", "passt"],
                [str(tcp.address[1]), str(udp.address[1])]) as vm:
            vm.finish("OUTBOUND6_OK")
        require(not tcp.errors and not udp.errors, f"IPv6 echo errors: {tcp.errors + udp.errors}")


PUBLISHED_GUEST = r"""
    from pathlib import Path
    import selectors, socket, sys, time
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('0.0.0.0', int(sys.argv[1])))
    tcp.listen(8)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('0.0.0.0', int(sys.argv[2])))
    selector = selectors.DefaultSelector()
    selector.register(tcp, selectors.EVENT_READ)
    selector.register(udp, selectors.EVENT_READ)
    Path('ready').write_text('ready', encoding='ascii')
    deadline = time.monotonic() + 20
    tcp_seen = udp_seen = False
    while not Path('stop').exists():
        assert time.monotonic() < deadline, 'host did not finish published-port test'
        for key, _ in selector.select(0.1):
            if key.fileobj is tcp:
                peer, _ = tcp.accept()
                with peer:
                    peer.settimeout(3)
                    while data := peer.recv(65536):
                        peer.sendall(data)
                    peer.sendall(b'<EOF>')
                    peer.shutdown(socket.SHUT_WR)
                    tcp_seen = True
            else:
                data, sender = udp.recvfrom(65535)
                udp.sendto(data, sender)
                udp_seen = True
    assert tcp_seen and udp_seen, 'one published protocol was not exercised'
    print('PUBLISH_OK', flush=True)
"""


def available_port(kind: int, avoid: set[int] | None = None) -> int:
    for _ in range(20):
        with socket.socket(socket.AF_INET, kind) as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
            if avoid and port in avoid:
                continue
            # Ensure the undeclared-protocol assertion won't collide with a
            # pre-existing local service using the same numeric port.
            other_kind = socket.SOCK_DGRAM if kind == socket.SOCK_STREAM else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, other_kind) as other:
                try:
                    other.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port
    raise RuntimeError("could not select independent temporary ports")


def test_published_ports(binary: Path, case: Path) -> None:
    host_tcp = available_port(socket.SOCK_STREAM)
    host_udp = available_port(socket.SOCK_DGRAM, {host_tcp})
    guest_tcp, guest_udp = 41023, 41024
    options = ["--network", "passt", "-p", f"127.0.0.1:{host_tcp}:{guest_tcp}/tcp",
               "-p", f"127.0.0.1:{host_udp}:{guest_udp}/udp"]
    with VM(binary, case, PUBLISHED_GUEST, options, [str(guest_tcp), str(guest_udp)]) as vm:
        vm.wait_file("ready")
        # Publishing TCP must not also bind UDP at the same host port. A fresh
        # UDP socket without SO_REUSE* can bind only if passt left it unclaimed.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unpublished:
            unpublished.bind(("127.0.0.1", host_tcp))
            with socket.create_connection(("127.0.0.1", host_tcp), timeout=vm.operation_timeout()) as peer:
                payload = bytes(range(256)) * 61
                peer.sendall(payload)
                peer.shutdown(socket.SHUT_WR)
                require(receive_all(peer) == payload + EOF_MARKER, "published TCP response mismatch")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                peer.settimeout(vm.operation_timeout())
                payload = b"published-udp\x00" * 53
                peer.sendto(payload, ("127.0.0.1", host_udp))
                require(peer.recv(4096) == payload, "published UDP response mismatch")
        (vm.work / "stop").write_text("stop", encoding="ascii")
        vm.finish("PUBLISH_OK")


SSH_GUEST = r"""
    import concurrent.futures, os, socket, stat, sys
    expected_uid, upstream = int(sys.argv[1]), sys.argv[2]
    assert os.getuid() == expected_uid, 'guest UID changed'
    assert os.getgid() == int(sys.argv[3]), 'guest GID changed'
    endpoint = os.environ['SSH_AUTH_SOCK']
    assert endpoint == '/run/user/%d/ssh-agent.socket' % expected_uid, 'SSH alias path changed'
    assert endpoint != upstream and not os.path.exists(upstream), 'host agent path exposed'
    endpoints = (endpoint, '/run/custom/service.socket')
    for path in endpoints:
        info = os.stat(path)
        assert stat.S_ISSOCK(info.st_mode), 'guest endpoint is not a Unix socket'
        assert info.st_uid == expected_uid and stat.S_IMODE(info.st_mode) == 0o600
    assert 'eth0' not in dict(socket.if_nameindex()).values(), 'network none has a NIC'

    def round_trip(index):
        payload = bytes((i * 37 + index) % 251 for i in range(256 * 1024 + index))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(8)
            peer.connect(endpoints[index % len(endpoints)])
            def send():
                peer.sendall(payload)
                peer.shutdown(socket.SHUT_WR)
            # Independent writing exercises backpressure without deadlocking a
            # stream echo once both socket buffers have filled.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as sender:
                pending = sender.submit(send)
                response = bytearray()
                while data := peer.recv(65536):
                    response.extend(data)
                pending.result(timeout=1)
            assert response == payload + b'<EOF>', (
                'SSH stream or half-close response lost: client=%d got=%d expected=%d tail=%r'
                % (index, len(response), len(payload) + 5, response[-16:]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as clients:
        list(clients.map(round_trip, range(6)))
    print('SSH_OK uid=' + str(os.getuid()) + ' socket=' + endpoint, flush=True)
"""


def test_ssh(binary: Path, case: Path) -> None:
    private = case / "private"
    private.mkdir(mode=0o700)
    endpoint = str(private / "fake-agent.sock")
    with EchoService(socket.AF_UNIX, socket.SOCK_STREAM, endpoint) as agent:
        os.chmod(endpoint, 0o600)
        with VM(binary, case, SSH_GUEST, ["--network", "none", "--socket",
                f"src={endpoint},dst=/run/custom/service.socket", "--ssh-agent"],
                [str(os.getuid()), endpoint, str(os.getgid())], {"SSH_AUTH_SOCK": endpoint}) as vm:
            try:
                vm.finish("SSH_OK")
            except Exception:
                print(f"Fake SSH server (received bytes, EOF marker sent): {agent.completed}; errors: {agent.errors}", file=sys.stderr)
                raise
        require(not agent.errors, f"fake SSH endpoint errors: {agent.errors}")


SOCKETS_GUEST = r"""
    from pathlib import Path
    import concurrent.futures, os, socket, stat, sys, time
    expected_uid, expected_gid = int(sys.argv[1]), int(sys.argv[2])
    endpoints = sys.argv[3:]
    assert os.getuid() == expected_uid and os.getgid() == expected_gid
    assert os.environ['SSH_AUTH_SOCK'] == endpoints[0], 'explicit socket environment lost'
    assert 'eth0' not in dict(socket.if_nameindex()).values(), 'network none has a NIC'
    info = os.stat('/run')
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o755), (
        'existing /run metadata changed')
    assert not Path('/srv/readonly/cache/host-only').exists(), 'covered host data exposed through tmpfs'
    for endpoint in endpoints:
        info = os.stat(endpoint)
        assert stat.S_ISSOCK(info.st_mode), 'forwarded endpoint is not a Unix socket'
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
            expected_uid, expected_gid, 0o600), 'socket owner or mode mismatch'
        for parent in Path(endpoint).parents:
            if parent in (Path('/'), Path('/run'), Path('/srv/shared'), Path('/srv/readonly')):
                break
            info = parent.stat()
            assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
                expected_uid, expected_gid, 0o700), 'new directory owner or mode mismatch'

    def round_trip(index, markers):
        selected = index % len(endpoints)
        payload = bytes((i * 31 + index) % 251 for i in range(256 * 1024 + index))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(8)
            peer.connect(endpoints[selected])
            def send():
                peer.sendall(payload)
                peer.shutdown(socket.SHUT_WR)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as sender:
                pending = sender.submit(send)
                response = bytearray()
                while data := peer.recv(65536):
                    response.extend(data)
                pending.result(timeout=1)
            assert response == payload + markers[selected], (
                'forwarded stream, route, or half-close mismatch: client=%d length=%d tail=%r'
                % (index, len(response), response[-16:]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as clients:
        list(clients.map(lambda index: round_trip(index, (
            b'<FIRST>', b'<SECOND>', b'<FIRST>', b'<SECOND>', b'<FIRST>')), range(10)))
    Path('initial-complete').write_text('ready', encoding='ascii')
    deadline = time.monotonic() + 10
    while not Path('upstream-replaced').exists():
        assert time.monotonic() < deadline, 'host did not replace upstream socket'
        time.sleep(0.02)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as clients:
        list(clients.map(lambda index: round_trip(index, (
            b'<REPLACED>', b'<SECOND>', b'<REPLACED>', b'<SECOND>', b'<REPLACED>')), range(10)))
    print('SOCKETS_OK', flush=True)
"""


def test_sockets(binary: Path, case: Path) -> None:
    private = case / "private"
    private.mkdir(mode=0o700)
    shared_parent = case / "shared-parent"
    shared_parent.mkdir(mode=0o751)
    shared_before = shared_parent.stat()
    readonly = case / "readonly-parent"
    readonly_cache = readonly / "cache"
    readonly_cache.mkdir(parents=True)
    readonly_cache.chmod(0o751)
    (readonly_cache / "host-only").write_text("host-data", encoding="ascii")
    readonly_before = readonly_cache.stat()
    # A 74-byte runtime directory fits control.sock but not socket-0.sock
    # after the private directory suffix, so startup must select a fallback.
    runtime = case / ("runtime-" + "x" * (74 - len(str(case.resolve())) - len("/runtime-")))
    runtime.mkdir(mode=0o700)
    require(len(str(runtime.resolve())) == 74, "runtime regression fixture path has unexpected length")
    upstreams = [str(private / "first.sock"), str(private / "second.sock")]
    endpoints = ["/run/agent-vm-sockets/first/nested/service.socket",
                 "/run/agent-vm-sockets/second/service.socket",
                 "/srv/shared/nested/service.socket",
                 "/socket-cache/nested/service.socket",
                 "/srv/readonly/cache/nested/service.socket"]
    options = ["--network", "none", "--no-ssh-agent", "-e", f"SSH_AUTH_SOCK={endpoints[0]}",
               "--mount", f"src={shared_parent},dst=/srv/shared,rw",
               "--mount", f"src={readonly},dst=/srv/readonly,ro",
               "--tmpfs", "target=/socket-cache", "--tmpfs", "target=/srv/readonly/cache"]
    for upstream, endpoint in zip([*upstreams, upstreams[0], upstreams[1], upstreams[0]], endpoints):
        options.extend(["--socket", f"src={upstream},dst={endpoint}"])
    first = EchoService(socket.AF_UNIX, socket.SOCK_STREAM, upstreams[0], b"<FIRST>")
    try:
        with EchoService(socket.AF_UNIX, socket.SOCK_STREAM, upstreams[1], b"<SECOND>") as second:
            with VM(binary, case, SOCKETS_GUEST, options,
                    [str(os.getuid()), str(os.getgid()), *endpoints],
                    {"XDG_RUNTIME_DIR": str(runtime)}) as vm:
                vm.wait_file("initial-complete")
                require(not first.errors, f"first socket service errors: {first.errors}")
                first.__exit__()
                os.unlink(upstreams[0])
                first = EchoService(socket.AF_UNIX, socket.SOCK_STREAM, upstreams[0], b"<REPLACED>")
                (vm.work / "upstream-replaced").write_text("ready", encoding="ascii")
                vm.finish("SOCKETS_OK")
            shared_after = shared_parent.stat()
            require((shared_after.st_ino, shared_after.st_uid, shared_after.st_gid, shared_after.st_mode) ==
                    (shared_before.st_ino, shared_before.st_uid, shared_before.st_gid, shared_before.st_mode),
                    "existing shared socket parent metadata changed")
            readonly_after = readonly_cache.stat()
            require((readonly_after.st_ino, readonly_after.st_uid, readonly_after.st_gid,
                     readonly_after.st_mode, readonly_after.st_mtime_ns, readonly_after.st_ctime_ns) ==
                    (readonly_before.st_ino, readonly_before.st_uid, readonly_before.st_gid,
                     readonly_before.st_mode, readonly_before.st_mtime_ns, readonly_before.st_ctime_ns),
                    "tmpfs-backed socket changed covered host directory metadata")
            require(sorted(p.name for p in readonly_cache.iterdir()) == ["host-only"] and
                    (readonly_cache / "host-only").read_text(encoding="ascii") == "host-data",
                    "tmpfs-backed socket changed covered host directory contents")
            require(not first.errors and not second.errors,
                    f"socket service errors: {first.errors + second.errors}")

            failure = case / "preexisting"
            failure.mkdir(mode=0o700)
            shared = failure / "shared"
            shared.mkdir(mode=0o751)
            occupied = shared / "service.socket"
            occupied.write_bytes(b"existing destination must survive\n")
            occupied.chmod(0o640)
            before_parent, before_file = shared.stat(), occupied.stat()
            failure_options = ["--network", "none", "--mount", f"src={shared},dst=/srv/shared,rw",
                               "--socket", f"src={upstreams[1]},dst=/srv/shared/service.socket"]
            with VM(binary, failure, "from pathlib import Path; Path('unexpected-workload').touch()",
                    failure_options) as vm:
                code = vm.process.wait(timeout=vm.operation_timeout(25))
                vm.stderr.flush()
                errors = (failure / "stderr.log").read_text(encoding="utf-8", errors="replace")
                require(code != 0, "preexisting socket destination was accepted")
                require("socket" in errors.lower(), f"missing socket failure diagnostic: {errors}")
                require(not (vm.work / "unexpected-workload").exists(),
                        "workload started despite preexisting socket destination")
            require(occupied.read_bytes() == b"existing destination must survive\n",
                    "preexisting destination contents changed")
            for path, before in ((shared, before_parent), (occupied, before_file)):
                after = path.stat()
                require((after.st_ino, after.st_uid, after.st_gid, after.st_mode) ==
                        (before.st_ino, before.st_uid, before.st_gid, before.st_mode),
                        f"preexisting destination metadata changed: {path}")

            partial = case / "partial-start"
            partial.mkdir(mode=0o700)
            shared = partial / "shared"
            shared.mkdir(mode=0o751)
            partial_options = ["--network", "none", "--mount", f"src={shared},dst=/srv/shared,rw",
                               "--socket", f"src={upstreams[1]},dst=/srv/shared/new/first.socket",
                               "--socket", f"src={upstreams[1]},dst=/run/denied.socket"]
            with VM(binary, partial, "from pathlib import Path; Path('unexpected-workload').touch()",
                    partial_options) as vm:
                code = vm.process.wait(timeout=vm.operation_timeout(25))
                vm.stderr.flush()
                errors = (partial / "stderr.log").read_text(encoding="utf-8", errors="replace")
                require(code != 0, "socket creation under root-owned /run was accepted")
                require("/run/denied.socket" in errors and "Permission denied" in errors,
                        f"missing guest socket permission diagnostic: {errors}")
                require(not (vm.work / "unexpected-workload").exists(),
                        "workload started after partial socket startup failed")
            require((shared / "new").is_dir(), "guest never prepared the shared socket directory")
            require(not (shared / "new/first.socket").exists(),
                    "first socket survived partial startup cleanup")
    finally:
        first.__exit__()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "build/agent-vm")
    parser.add_argument("--case", choices=("outbound", "outbound6", "publish", "ssh", "sockets"), help="run a single case")
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"agent-vm binary is not executable: {binary}")
    root = Path(tempfile.mkdtemp(prefix="avm-net-integration."))
    cases = [("outbound", test_outbound), ("outbound6", test_outbound6), ("publish", test_published_ports), ("ssh", test_ssh),
             ("sockets", test_sockets)]
    try:
        for name, test in cases:
            if arguments.case and arguments.case != name:
                continue
            case = root / name
            case.mkdir(mode=0o700)
            started = time.monotonic()
            test(binary, case)
            print(f"PASS {name} ({time.monotonic() - started:.1f}s)", flush=True)
    except Exception as error:
        print(f"FAIL {name}: {error}", file=sys.stderr)
        for log_name in ("stdout.log", "stderr.log"):
            log = case / log_name
            if log.exists():
                print(f"--- {name} {log_name} ---", file=sys.stderr)
                print(log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        print(f"Failure fixtures and logs retained at {root}", file=sys.stderr)
        return 1
    shutil.rmtree(root)
    print("Real-VM network integration tests passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

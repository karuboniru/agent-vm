#!/usr/bin/env python3
"""Real-VM passt and SSH tests using only disposable local echo services.

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

    def __init__(self, family: int, kind: int, address: object):
        self.kind = kind
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
                connection.sendall(EOF_MARKER)
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
    assert endpoint != upstream and not os.path.exists(upstream), 'host agent path exposed'
    info = os.stat(endpoint)
    assert stat.S_ISSOCK(info.st_mode), 'guest endpoint is not a Unix socket'
    assert info.st_uid == expected_uid and stat.S_IMODE(info.st_mode) == 0o600
    assert 'eth0' not in dict(socket.if_nameindex()).values(), 'network none has a NIC'

    def round_trip(index):
        payload = bytes((i * 37 + index) % 251 for i in range(256 * 1024 + index))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(8)
            peer.connect(endpoint)
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
        with VM(binary, case, SSH_GUEST, ["--network", "none", "--ssh-agent"],
                [str(os.getuid()), endpoint, str(os.getgid())], {"SSH_AUTH_SOCK": endpoint}) as vm:
            try:
                vm.finish("SSH_OK")
            except Exception:
                print(f"Fake SSH server (received bytes, EOF marker sent): {agent.completed}; errors: {agent.errors}", file=sys.stderr)
                raise
        require(not agent.errors, f"fake SSH endpoint errors: {agent.errors}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "build/agent-vm")
    parser.add_argument("--case", choices=("outbound", "publish", "ssh"), help="run a single case")
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"agent-vm binary is not executable: {binary}")
    root = Path(tempfile.mkdtemp(prefix="avm-net-integration."))
    cases = [("outbound", test_outbound), ("publish", test_published_ports), ("ssh", test_ssh)]
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

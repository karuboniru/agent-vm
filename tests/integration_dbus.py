#!/usr/bin/env python3
"""Isolated D-Bus tests through real VM/vsock, never using the desktop bus.

Use --daemon-prefix toolbox run when dbus-daemon is installed in toolbox.
Requires host xdg-dbus-proxy, gdbus, KVM and unprivileged namespaces.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'build/agent-vm')
parser.add_argument('--daemon-prefix', nargs='*', default=[])
args = parser.parse_args()
binary = str(args.binary.resolve())
with tempfile.TemporaryDirectory(prefix='avm-dbus-') as tmp:
    root = Path(tmp)
    home = root / 'home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home))
    for key in ('DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS'):
        env.pop(key, None)
    daemon = subprocess.Popen(args.daemon_prefix + ['dbus-daemon', '--session', '--nofork',
        '--address=unix:path=' + str(root / 'bus'), '--print-address=1'], stdout=subprocess.PIPE, text=True)
    connection = None
    try:
        address = daemon.stdout.readline().strip()
        assert address.startswith('unix:'), address
        # Hold two host-side names on the disposable bus to test visibility.
        dbus = ctypes.CDLL('libdbus-1.so.3')
        dbus.dbus_connection_open_private.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        dbus.dbus_connection_open_private.restype = ctypes.c_void_p
        dbus.dbus_bus_register.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        dbus.dbus_bus_request_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p]
        dbus.dbus_connection_close.argtypes = [ctypes.c_void_p]
        dbus.dbus_connection_unref.argtypes = [ctypes.c_void_p]
        connection = dbus.dbus_connection_open_private(address.encode(), None)
        assert connection and dbus.dbus_bus_register(connection, None)
        for name in (b'org.example.Visible', b'org.example.Hidden'):
            assert dbus.dbus_bus_request_name(connection, name, 0, None) == 1
        config = root / 'config.toml'
        def run(user, system, command, success=True):
            config.write_text('\n'.join(
                f'[dbus.{name}]\nenabled = {str(enabled).lower()}\naddress = {json.dumps(address)}\n'
                f'args = ["--own=org.example.{name}Allowed", "--see=org.example.Visible"]\n'
                for name, enabled in [('user', user), ('system', system)]))
            result = subprocess.run([binary, 'run', '--config', str(config), '--cwd-mode', 'none',
                '--cpus', '1', '--memory', '512', '--', *command], env=env,
                capture_output=True, text=True, timeout=35)
            assert (result.returncode == 0) == success, (command, result.returncode, result.stdout, result.stderr)
            return result
        for name, flag in [('user', '--session'), ('system', '--system')]:
            def call(member, *values):
                return ['gdbus', 'call', flag, '--dest', 'org.freedesktop.DBus', '--object-path',
                        '/org/freedesktop/DBus', '--method', 'org.freedesktop.DBus.' + member, *values]
            result = run(True, True, call('ListNames'))
            assert 'org.example.Visible' in result.stdout and 'org.example.Hidden' not in result.stdout, result.stdout
            result = run(True, True, call('RequestName', f'org.example.{name}Allowed', '0'))
            assert 'uint32 1' in result.stdout, result.stdout
            result = run(True, True, call('RequestName', 'org.example.Denied', '0'), False)
            assert any(error in result.stderr for error in ('AccessDenied', 'ServiceUnknown')), result.stderr
        for user, system in [(True, False), (False, True), (False, False)]:
            code = ('import os; '
                    f'assert ("DBUS_SESSION_BUS_ADDRESS" in os.environ) == {user}; '
                    f'assert ("DBUS_SYSTEM_BUS_ADDRESS" in os.environ) == {system}')
            run(user, system, ['python3', '-c', code])
        print('D-Bus VM tests passed: both buses, allowed/denied names, independent switches and environment')
    finally:
        if connection:
            dbus.dbus_connection_close(connection)
            dbus.dbus_connection_unref(connection)
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()

#!/usr/bin/env python3
"""Exercise Wayland forwarding through a real VM and a disposable Weston.

Run on a host with /dev/kvm, waypipe, Weston headless, and libwayland-client:
    python3 tests/integration_wayland.py --binary /absolute/path/to/agent-vm
Add --xwayland-satellite to exercise X11 through xwayland-satellite and Xwayland.

Missing optional Wayland prerequisites exit 77. A configured test failure does
not skip: VM startup, protocol errors, timeouts, and wrong statuses fail.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import re
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


GUEST_CLIENT = r'''
import ctypes
import mmap
import os
import sys
import time

class Interface(ctypes.Structure):
    _fields_ = [('name', ctypes.c_char_p), ('version', ctypes.c_int),
                ('method_count', ctypes.c_int), ('methods', ctypes.c_void_p),
                ('event_count', ctypes.c_int), ('events', ctypes.c_void_p)]

class Message(ctypes.Structure):
    _fields_ = [('name', ctypes.c_char_p), ('signature', ctypes.c_char_p),
                ('types', ctypes.c_void_p)]

lib = ctypes.CDLL('libwayland-client.so.0')
lib.wl_display_connect.argtypes = [ctypes.c_char_p]
lib.wl_display_connect.restype = ctypes.c_void_p
lib.wl_display_disconnect.argtypes = [ctypes.c_void_p]
lib.wl_display_roundtrip.argtypes = [ctypes.c_void_p]
lib.wl_display_roundtrip.restype = ctypes.c_int
lib.wl_display_get_error.argtypes = [ctypes.c_void_p]
lib.wl_display_get_error.restype = ctypes.c_int
lib.wl_proxy_add_listener.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
lib.wl_proxy_add_listener.restype = ctypes.c_int
lib.wl_proxy_marshal_constructor_versioned.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                                         ctypes.c_void_p, ctypes.c_uint32]
lib.wl_proxy_marshal_constructor_versioned.restype = ctypes.c_void_p
lib.wl_proxy_marshal.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

# xdg-shell is a separate protocol, so libwayland-client does not export its
# interface tables. Keep the version-1 wire descriptions alive for each proxy.
interfaces = {}
def protocol_interface(name, methods, events):
    requests = (Message * len(methods))(
        *(Message(item.encode(), signature.encode(), None) for item, signature in methods))
    replies = (Message * len(events))(
        *(Message(item.encode(), signature.encode(), None) for item, signature in events))
    interface = Interface(name.encode(), 1, len(methods), ctypes.addressof(requests),
                          len(events), ctypes.addressof(replies))
    interfaces[name] = (interface, requests, replies)

protocol_interface('xdg_wm_base',
                   [('destroy', ''), ('create_positioner', 'n'),
                    ('get_xdg_surface', 'no'), ('pong', 'u')], [('ping', 'u')])
protocol_interface('xdg_surface',
                   [('destroy', ''), ('get_toplevel', 'n'), ('get_popup', 'noo'),
                    ('set_window_geometry', 'iiii'), ('ack_configure', 'u')],
                   [('configure', 'u')])
protocol_interface('xdg_toplevel',
                   [('destroy', ''), ('set_parent', '?o'), ('set_title', 's'),
                    ('set_app_id', 's'), ('show_window_menu', 'ouii'), ('move', 'ou'),
                    ('resize', 'ouu'), ('set_max_size', 'ii'), ('set_min_size', 'ii'),
                    ('set_maximized', ''), ('unset_maximized', ''),
                    ('set_fullscreen', '?o'), ('unset_fullscreen', ''),
                    ('set_minimized', '')], [('configure', 'iia'), ('close', '')])

def iface(name):
    if name in interfaces:
        return ctypes.addressof(interfaces[name][0])
    return ctypes.addressof(Interface.in_dll(lib, name + '_interface'))

def create(proxy, opcode, interface, *args):
    result = lib.wl_proxy_marshal_constructor_versioned(
        proxy, opcode, iface(interface), 1, *args)
    assert result, 'cannot create ' + interface
    return result

assert os.environ.get('WAYLAND_DISPLAY'), 'waypipe did not set WAYLAND_DISPLAY'
assert os.environ.get('XDG_RUNTIME_DIR'), 'guest runtime directory is missing'

for attempt in range(3):
    display = lib.wl_display_connect(None)
    assert display, 'Wayland connection %d failed' % attempt
    try:
        registry = create(display, 1, 'wl_registry', ctypes.c_void_p())
        globals = {}
        GLOBAL = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32)
        REMOVE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
        def on_global(_data, _registry, name, interface, version):
            globals[interface.decode()] = (name, version)
        def on_remove(_data, _registry, _name):
            pass
        # Keep callback objects alive while libwayland dispatches registry events.
        global_callback = GLOBAL(on_global)
        remove_callback = REMOVE(on_remove)
        callbacks = (ctypes.c_void_p * 2)(
            ctypes.cast(global_callback, ctypes.c_void_p).value,
            ctypes.cast(remove_callback, ctypes.c_void_p).value)
        assert lib.wl_proxy_add_listener(registry, callbacks, None) == 0
        assert lib.wl_display_roundtrip(display) >= 0, 'registry roundtrip failed'
        assert all(name in globals for name in ('wl_compositor', 'wl_shm', 'xdg_wm_base')), globals

        def bind(name):
            number, version = globals[name]
            assert version >= 1
            return create(registry, 0, name, ctypes.c_uint32(number),
                          ctypes.c_char_p(name.encode()), ctypes.c_uint32(1),
                          ctypes.c_void_p())

        compositor = bind('wl_compositor')
        shm = bind('wl_shm')
        wm_base = bind('xdg_wm_base')
        surface = create(compositor, 0, 'wl_surface', ctypes.c_void_p())
        xdg_surface = create(wm_base, 2, 'xdg_surface', ctypes.c_void_p(),
                             ctypes.c_void_p(surface))
        toplevel = create(xdg_surface, 1, 'xdg_toplevel', ctypes.c_void_p())
        configured = [False]
        closed = [False]
        PING = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
        CONFIGURE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_uint32)
        TOPLEVEL_CONFIGURE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_int32, ctypes.c_int32, ctypes.c_void_p)
        CLOSE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
        def on_ping(_data, _base, serial):
            lib.wl_proxy_marshal(wm_base, 3, ctypes.c_uint32(serial))
        def on_configure(_data, _surface, serial):
            lib.wl_proxy_marshal(xdg_surface, 4, ctypes.c_uint32(serial))
            configured[0] = True
        def on_toplevel_configure(_data, _toplevel, _width, _height, _states):
            pass
        def on_close(_data, _toplevel):
            closed[0] = True
        ping_callback = PING(on_ping)
        configure_callback = CONFIGURE(on_configure)
        toplevel_configure_callback = TOPLEVEL_CONFIGURE(on_toplevel_configure)
        close_callback = CLOSE(on_close)
        wm_callbacks = (ctypes.c_void_p * 1)(ctypes.cast(ping_callback, ctypes.c_void_p).value)
        surface_callbacks = (ctypes.c_void_p * 1)(ctypes.cast(configure_callback, ctypes.c_void_p).value)
        toplevel_callbacks = (ctypes.c_void_p * 2)(
            ctypes.cast(toplevel_configure_callback, ctypes.c_void_p).value,
            ctypes.cast(close_callback, ctypes.c_void_p).value)
        assert lib.wl_proxy_add_listener(wm_base, wm_callbacks, None) == 0
        assert lib.wl_proxy_add_listener(xdg_surface, surface_callbacks, None) == 0
        assert lib.wl_proxy_add_listener(toplevel, toplevel_callbacks, None) == 0
        lib.wl_proxy_marshal(toplevel, 2, ctypes.c_char_p(b'agent-vm Wayland integration'))
        lib.wl_proxy_marshal(surface, 6)  # xdg_surface initial commit, no buffer
        for _ in range(5):
            assert lib.wl_display_roundtrip(display) >= 0, 'initial configure failed'
            if configured[0]:
                break
        assert configured[0], 'xdg_surface was not configured'

        width = height = 256
        size = width * height * 4
        fd = os.memfd_create('avm-wayland-test', os.MFD_CLOEXEC)
        try:
            os.ftruncate(fd, size)
            with mmap.mmap(fd, size) as pixels:
                colors = bytearray(os.urandom(size))
                colors[3::4] = b'\xff' * (width * height)
                pixels[:] = colors
            pool = create(shm, 0, 'wl_shm_pool', ctypes.c_void_p(),
                          ctypes.c_int(fd), ctypes.c_int(size))
            buffer = create(pool, 0, 'wl_buffer', ctypes.c_void_p(),
                            ctypes.c_int(0), ctypes.c_int(width),
                            ctypes.c_int(height), ctypes.c_int(width * 4),
                            ctypes.c_uint32(0))  # ARGB8888
            lib.wl_proxy_marshal(surface, 1, ctypes.c_void_p(buffer), ctypes.c_int(0),
                                 ctypes.c_int(0))  # attach
            lib.wl_proxy_marshal(surface, 2, ctypes.c_int(0), ctypes.c_int(0),
                                 ctypes.c_int(width), ctypes.c_int(height))  # damage
            frame = create(surface, 3, 'wl_callback', ctypes.c_void_p())
            frame_done = [False]
            DONE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_uint32)
            def on_frame(_data, _callback, _time):
                frame_done[0] = True
            frame_callback = DONE(on_frame)
            frame_callbacks = (ctypes.c_void_p * 1)(
                ctypes.cast(frame_callback, ctypes.c_void_p).value)
            assert lib.wl_proxy_add_listener(frame, frame_callbacks, None) == 0
            lib.wl_proxy_marshal(surface, 6)  # commit
            deadline = time.monotonic() + 8
            while not frame_done[0] and time.monotonic() < deadline:
                assert lib.wl_display_roundtrip(display) >= 0, 'surface roundtrip failed'
                if not frame_done[0]:
                    time.sleep(0.02)
            assert frame_done[0], 'mapped surface received no frame callback'
            assert not closed[0], 'compositor closed the test window'
            assert lib.wl_display_get_error(display) == 0, 'Wayland protocol error'
        finally:
            os.close(fd)
        print('WAYLAND_COMMIT_%d' % attempt, flush=True)
    finally:
        lib.wl_display_disconnect(display)

if len(sys.argv) > 2 and sys.argv[2] == 'x11':
    assert os.environ.get('DISPLAY', '').startswith(':'), 'waypipe did not set guest DISPLAY'
    xlib = ctypes.CDLL('libX11.so.6')
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XDefaultScreen.argtypes = [ctypes.c_void_p]
    xlib.XDefaultScreen.restype = ctypes.c_int
    xlib.XRootWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
    xlib.XRootWindow.restype = ctypes.c_ulong
    xlib.XCreateSimpleWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                         ctypes.c_int, ctypes.c_int, ctypes.c_uint,
                                         ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong,
                                         ctypes.c_ulong]
    xlib.XCreateSimpleWindow.restype = ctypes.c_ulong
    xlib.XSelectInput.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_long]
    xlib.XMapWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    xlib.XPending.argtypes = [ctypes.c_void_p]
    xlib.XPending.restype = ctypes.c_int
    xlib.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    xlib.XDestroyWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    for attempt in range(3):
        xdisplay = xlib.XOpenDisplay(None)
        assert xdisplay, 'X11 connection %d failed on %s' % (attempt, os.environ['DISPLAY'])
        try:
            root = xlib.XRootWindow(xdisplay, xlib.XDefaultScreen(xdisplay))
            window = xlib.XCreateSimpleWindow(xdisplay, root, 0, 0, 64, 64, 0, 0, 0)
            assert window, 'XCreateSimpleWindow failed'
            try:
                xlib.XSelectInput(xdisplay, window, 1 << 17)  # StructureNotifyMask
                xlib.XMapWindow(xdisplay, window)
                xlib.XSync(xdisplay, 0)
                mapped = False
                deadline = time.monotonic() + 8
                event = ctypes.create_string_buffer(256)  # larger than XEvent
                while time.monotonic() < deadline:
                    if xlib.XPending(xdisplay):
                        xlib.XNextEvent(xdisplay, event)
                        if ctypes.c_int.from_buffer(event).value == 19:  # MapNotify
                            mapped = True
                            break
                    else:
                        time.sleep(0.02)
                assert mapped, 'X11 window received no MapNotify'
            finally:
                xlib.XDestroyWindow(xdisplay, window)
                xlib.XSync(xdisplay, 0)
        finally:
            xlib.XCloseDisplay(xdisplay)
        print('X11_MAP_%d' % attempt, flush=True)

if sys.argv[1] == 'signal':
    print('READY_FOR_SIGNAL', flush=True)
    time.sleep(60)
elif sys.argv[1] == 'exit':
    sys.exit(37)
'''

VULKAN_CLIENT = r'''
import os
import subprocess
report = subprocess.run(['vulkaninfo', '--summary'], check=True, capture_output=True,
                        text=True, timeout=15).stdout
device = report.split('GPU0:', 1)[1].split('GPU1:', 1)[0]
assert 'Venus' in device and 'PHYSICAL_DEVICE_TYPE_CPU' not in device, device
assert not any(name in device.lower() for name in ('llvmpipe', 'lavapipe', 'softpipe')), device
print('HARDWARE_VENUS_CONFIRMED', flush=True)
os.execvp('vkcube', ['vkcube', '--wsi', 'wayland', '--c', '30', '--gpu_number', '0'])
'''


def skip(message: str) -> None:
    print('SKIP Wayland integration: ' + message, flush=True)
    raise SystemExit(77)


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def run_vm(command: list[str], environment: dict[str, str], expected: int,
           *, signal_case: bool = False, x11_case: bool = False) -> None:
    process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        if signal_case:
            assert process.stdout is not None
            deadline = time.monotonic() + 45
            output = bytearray()
            while b'READY_FOR_SIGNAL\n' not in output:
                remaining = deadline - time.monotonic()
                assert remaining > 0, 'guest did not reach signal checkpoint'
                readable, _, _ = select.select([process.stdout], [], [], remaining)
                assert readable, 'guest did not reach signal checkpoint'
                chunk = os.read(process.stdout.fileno(), 4096)
                assert chunk, f'VM ended before signal checkpoint: {output!r}'
                output.extend(chunk)
            process.send_signal(signal.SIGTERM)
            rest, error = process.communicate(timeout=15)
            output.extend(rest)
        else:
            output, error = process.communicate(timeout=45)
        assert process.returncode == expected, (
            f'VM returned {process.returncode}, expected {expected}; '
            f'stdout tail={output[-4000:]!r}; stderr tail={error[-4000:]!r}')
        for attempt in range(3):
            marker = ('WAYLAND_COMMIT_%d\n' % attempt).encode()
            assert marker in output, (
                f'missing {marker!r}; stdout tail={output[-4000:]!r}; '
                f'stderr tail={error[-4000:]!r}')
            if x11_case:
                marker = ('X11_MAP_%d\n' % attempt).encode()
                assert marker in output, (
                    f'missing {marker!r}; stdout tail={output[-4000:]!r}; '
                    f'stderr tail={error[-4000:]!r}')
    finally:
        stop(process)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'build/agent-vm')
    parser.add_argument('--gpu-flags', type=lambda value: int(value, 0),
                        help='also test accelerated DMA-BUF frames with these libkrun flags')
    parser.add_argument('--xwayland-satellite', action='store_true',
                        help='also create and map X11 windows via waypipe and xwayland-satellite')
    args = parser.parse_args()
    if args.gpu_flags is not None:
        assert 0 <= args.gpu_flags <= 0xffffffff, 'GPU flags must be a uint32'
        client = 'vkcube' if args.gpu_flags & 0x80 else 'es2gears_wayland'
        if not shutil.which(client):
            skip(client + ' is unavailable for the GPU case')
    binary = args.binary.resolve()
    assert binary.is_file() and os.access(binary, os.X_OK), f'missing executable: {binary}'
    if not shutil.which('weston'):
        skip('weston is unavailable')
    if not shutil.which('waypipe'):
        skip('waypipe is unavailable')
    if args.xwayland_satellite:
        if not shutil.which('xwayland-satellite'):
            skip('xwayland-satellite is unavailable')
        if not shutil.which('Xwayland'):
            skip('Xwayland is unavailable')
        try:
            ctypes.CDLL('libX11.so.6')
        except OSError:
            skip('libX11.so.6 is unavailable to the guest')
    try:
        ctypes.CDLL('libwayland-client.so.0')
    except OSError:
        skip('libwayland-client.so.0 is unavailable to the guest')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        skip('/dev/kvm is unavailable')

    with tempfile.TemporaryDirectory(prefix='avm-wl-') as tmp:
        root = Path(tmp)
        runtime = root / 'runtime'
        runtime.mkdir(mode=0o700)
        home = root / 'home'
        home.mkdir(mode=0o700)
        display = 'wayland-test'
        socket_path = runtime / display
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LANG': 'C.UTF-8',
                       'XDG_RUNTIME_DIR': str(runtime), 'WAYLAND_DISPLAY': display}
        log_path = root / 'weston.log'
        with log_path.open('wb') as log:
            weston_args = ['weston', '--backend=headless-backend.so']
            if args.gpu_flags is not None:
                weston_args.append('--renderer=gl')
            weston = subprocess.Popen([*weston_args,
                                       '--socket=' + display, '--idle-time=0',
                                       '--no-config', '--log=' + str(log_path)],
                                      env=environment, stdin=subprocess.DEVNULL,
                                      stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True)
            try:
                deadline = time.monotonic() + 10
                while not socket_path.is_socket() and weston.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                if not socket_path.is_socket() or weston.poll() is not None:
                    skip('Weston headless backend could not start: ' +
                         log_path.read_text(errors='replace')[-2000:])
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(2)
                    probe.connect(str(socket_path))

                command = [str(binary), 'run', '--no-config', '--wayland',
                           '--cwd-mode', 'none', '--cpus', '1', '--memory', '512',
                           '--', '/usr/bin/python3', '-u', '-c', GUEST_CLIENT]
                if args.xwayland_satellite:
                    command.insert(4, '--xwayland-satellite')
                if args.gpu_flags is not None:
                    command.insert(3, '--gpu=' + hex(args.gpu_flags))
                guest_options = ['x11'] if args.xwayland_satellite else []
                run_vm(command + ['exit', *guest_options], environment, 37,
                       x11_case=args.xwayland_satellite)
                assert weston.poll() is None, 'Weston exited during the exit-status case'
                run_vm(command + ['signal', *guest_options], environment, 143,
                       signal_case=True, x11_case=args.xwayland_satellite)
                assert weston.poll() is None, 'Weston exited during the signal case'
                if args.gpu_flags is not None:
                    venus = bool(args.gpu_flags & 0x80)  # NO_VIRGL: exercise Vulkan directly.
                    workload = (['python3', '-c', VULKAN_CLIENT]
                                if venus else ['timeout', '8', 'stdbuf', '-oL',
                                               'es2gears_wayland', '-info'])
                    gears = [str(binary), 'run', '--no-config', '--wayland',
                             '--gpu=' + hex(args.gpu_flags), '--cwd-mode', 'none',
                             '--cpus', '1', '--memory', '512', '-e', 'WAYLAND_DEBUG=1',
                             '--', *workload]
                    if args.xwayland_satellite:
                        gears.insert(4, '--xwayland-satellite')
                    result = subprocess.run(gears, env=environment, stdin=subprocess.DEVNULL,
                                            capture_output=True, timeout=30)
                    assert result.returncode == (0 if venus else 124), (
                        result.returncode, result.stdout[-4000:], result.stderr[-8000:])
                    if venus:
                        assert b'HARDWARE_VENUS_CONFIRMED' in result.stdout, result.stdout
                        assert result.stderr.count(b'.commit()') >= 30, result.stderr[-4000:]
                    else:
                        assert re.search(rb'[1-9][0-9]* frames in ', result.stdout), (
                            result.stdout[-4000:], result.stderr[-8000:])
                    assert b'zwp_linux_buffer_params_v1' in result.stderr, result.stderr[-4000:]
                    print('GPU Wayland passed: accelerated frames through DMA-BUF/waypipe/vsock', flush=True)
                print('Wayland VM tests passed: registry, mapped xdg_toplevel frames, '
                      'wl_shm FD buffers, reconnections, exit status and signal forwarding',
                      flush=True)
                if args.xwayland_satellite:
                    print('Xwayland satellite VM tests passed: guest DISPLAY, X11 mapped '
                          'windows, reconnections, exit status and signal forwarding', flush=True)
            finally:
                stop(weston)


if __name__ == '__main__':
    main()

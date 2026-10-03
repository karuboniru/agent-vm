#!/usr/bin/env python3
"""Exercise a real libkrun virtio-gpu through the guest DRM render node.

Run with a host GPU render node, /dev/kvm, and Mesa's GBM/EGL/OpenGL libraries:
    python3 tests/integration_gpu.py --binary /absolute/path/to/agent-vm

Missing host prerequisites exit 77. VM or rendering failures fail the test.
"""

from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile


GUEST_CLIENT = r'''
import ctypes
import os
from pathlib import Path
import stat

nodes = []
for path in sorted(Path('/dev/dri').glob('renderD*')):
    name = path.name
    if not name[7:].isdigit():
        continue
    info = path.lstat()
    if not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != 226 or os.minor(info.st_rdev) < 128:
        continue
    assert info.st_uid == os.getuid() and info.st_gid == os.getgid(), (path, info)
    assert stat.S_IMODE(info.st_mode) == 0o666, (path, oct(info.st_mode))
    nodes.append(path)
assert nodes, 'no guest DRM render node'
card = Path('/dev/dri/card0')
info = card.lstat()
assert stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 226 and os.minor(info.st_rdev) == 0, info
assert info.st_uid == os.getuid() and info.st_gid == os.getgid(), info
assert stat.S_IMODE(info.st_mode) == 0o660, oct(info.st_mode)
card_fd = os.open(card, os.O_RDWR | os.O_CLOEXEC)
os.close(card_fd)

gbm = ctypes.CDLL('libgbm.so.1')
egl = ctypes.CDLL('libEGL.so.1')
gl = ctypes.CDLL('libGL.so.1')
gbm.gbm_create_device.argtypes = [ctypes.c_int]
gbm.gbm_create_device.restype = ctypes.c_void_p
gbm.gbm_device_destroy.argtypes = [ctypes.c_void_p]
egl.eglGetProcAddress.argtypes = [ctypes.c_char_p]
egl.eglGetProcAddress.restype = ctypes.c_void_p
egl.eglInitialize.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
egl.eglInitialize.restype = ctypes.c_uint
egl.eglBindAPI.argtypes = [ctypes.c_uint]
egl.eglBindAPI.restype = ctypes.c_uint
egl.eglChooseConfig.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
                                ctypes.POINTER(ctypes.c_int)]
egl.eglChooseConfig.restype = ctypes.c_uint
egl.eglCreateContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.c_int)]
egl.eglCreateContext.restype = ctypes.c_void_p
egl.eglMakeCurrent.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_void_p]
egl.eglMakeCurrent.restype = ctypes.c_uint
egl.eglDestroyContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
egl.eglTerminate.argtypes = [ctypes.c_void_p]
gl.glGetString.argtypes = [ctypes.c_uint]
gl.glGetString.restype = ctypes.c_char_p
gl.glGenRenderbuffers.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
gl.glBindRenderbuffer.argtypes = [ctypes.c_uint, ctypes.c_uint]
gl.glRenderbufferStorage.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int, ctypes.c_int]
gl.glGenFramebuffers.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
gl.glBindFramebuffer.argtypes = [ctypes.c_uint, ctypes.c_uint]
gl.glFramebufferRenderbuffer.argtypes = [ctypes.c_uint, ctypes.c_uint,
                                         ctypes.c_uint, ctypes.c_uint]
gl.glCheckFramebufferStatus.argtypes = [ctypes.c_uint]
gl.glCheckFramebufferStatus.restype = ctypes.c_uint
gl.glClearColor.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.c_float,
                            ctypes.c_float]
gl.glClear.argtypes = [ctypes.c_uint]
gl.glReadPixels.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
gl.glGetError.restype = ctypes.c_uint
gl.glDeleteRenderbuffers.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
gl.glDeleteFramebuffers.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]

platform_address = egl.eglGetProcAddress(b'eglGetPlatformDisplayEXT')
assert platform_address, 'EGL_EXT_platform_base is unavailable'
get_platform_display = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint,
                                         ctypes.c_void_p, ctypes.c_void_p)(platform_address)

last_error = None
for node in nodes:
    fd = os.open(node, os.O_RDWR | os.O_CLOEXEC)
    device = None
    display = None
    context = None
    renderbuffer = ctypes.c_uint()
    framebuffer = ctypes.c_uint()
    try:
        device = gbm.gbm_create_device(fd)
        assert device, 'gbm_create_device failed'
        display = get_platform_display(0x31D7, device, None)  # EGL_PLATFORM_GBM_KHR
        assert display and egl.eglInitialize(display, None, None), 'EGL GBM initialization failed'
        assert egl.eglBindAPI(0x30A2), 'eglBindAPI(OpenGL) failed'
        attributes = (ctypes.c_int * 3)(0x3040, 0x0008, 0x3038)  # OPENGL_BIT, EGL_NONE
        config = ctypes.c_void_p()
        count = ctypes.c_int()
        assert egl.eglChooseConfig(display, attributes, ctypes.byref(config), 1,
                                   ctypes.byref(count)) and count.value == 1, 'no OpenGL EGL config'
        terminator = (ctypes.c_int * 1)(0x3038)
        context = egl.eglCreateContext(display, config, None, terminator)
        assert context, 'eglCreateContext failed'
        assert egl.eglMakeCurrent(display, None, None, context), 'surfaceless eglMakeCurrent failed'
        renderer = gl.glGetString(0x1F01)  # GL_RENDERER
        assert renderer, 'GL_RENDERER is missing'
        name = renderer.decode('utf-8', 'replace')
        lower = name.lower()
        assert 'virgl' in lower and not any(x in lower for x in
                                            ('llvmpipe', 'softpipe', 'swrast')), name
        # Read a pixel from an offscreen framebuffer so the driver must execute
        # a real GL command, even though the EGL context has no window surface.
        gl.glGenRenderbuffers(1, ctypes.byref(renderbuffer))
        gl.glBindRenderbuffer(0x8D41, renderbuffer)  # GL_RENDERBUFFER
        gl.glRenderbufferStorage(0x8D41, 0x8058, 1, 1)  # GL_RGBA8
        gl.glGenFramebuffers(1, ctypes.byref(framebuffer))
        gl.glBindFramebuffer(0x8D40, framebuffer)  # GL_FRAMEBUFFER
        gl.glFramebufferRenderbuffer(0x8D40, 0x8CE0, 0x8D41, renderbuffer)  # COLOR_ATTACHMENT0
        assert gl.glCheckFramebufferStatus(0x8D40) == 0x8CD5, 'offscreen framebuffer incomplete'
        gl.glClearColor(0.25, 0.5, 0.75, 1.0)
        gl.glClear(0x00004000)  # GL_COLOR_BUFFER_BIT
        pixel = (ctypes.c_ubyte * 4)()
        gl.glReadPixels(0, 0, 1, 1, 0x1908, 0x1401, pixel)  # GL_RGBA, GL_UNSIGNED_BYTE
        assert gl.glGetError() == 0, 'offscreen GL command failed'
        assert all(abs(actual - expected) <= 2 for actual, expected in
                   zip(pixel, (64, 128, 191, 255))), tuple(pixel)
        print('GPU_RENDERER=' + name, flush=True)
        break
    except (AssertionError, OSError) as error:
        last_error = error
    finally:
        if display and context:
            if framebuffer.value:
                gl.glDeleteFramebuffers(1, ctypes.byref(framebuffer))
            if renderbuffer.value:
                gl.glDeleteRenderbuffers(1, ctypes.byref(renderbuffer))
            egl.eglMakeCurrent(display, None, None, None)
        if display and context:
            egl.eglDestroyContext(display, context)
        if display:
            egl.eglTerminate(display)
        if device:
            gbm.gbm_device_destroy(device)
        os.close(fd)
else:
    raise AssertionError('no virtio-gpu render node provided VirGL OpenGL: %s' % last_error)
'''


def skip(message: str) -> None:
    print('SKIP GPU integration: ' + message, flush=True)
    raise SystemExit(77)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'build/agent-vm')
    parser.add_argument('--gpu-flags', type=lambda value: int(value, 0), default=0x10B,
                        help='raw libkrun VirGL flags (default: 0x10b, EGL/thread-sync/surfaceless/async)')
    args = parser.parse_args()
    assert 0 <= args.gpu_flags <= 0xFFFFFFFF, 'GPU flags must be a uint32'
    binary = args.binary.resolve()
    assert binary.is_file() and os.access(binary, os.X_OK), f'missing executable: {binary}'
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        skip('/dev/kvm is unavailable')
    host_nodes = [path for path in Path('/dev/dri').glob('renderD*')
                  if stat.S_ISCHR(path.stat().st_mode) and os.access(path, os.R_OK | os.W_OK)]
    if not host_nodes:
        skip('no accessible host DRM render node')
    for library in ('libgbm.so.1', 'libEGL.so.1', 'libGL.so.1'):
        try:
            ctypes.CDLL(library)
        except OSError:
            skip(f'{library} is unavailable to the guest')

    with tempfile.TemporaryDirectory(prefix='avm-gpu-') as temporary:
        home = Path(temporary) / 'home'
        home.mkdir(mode=0o700)
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LANG': 'C.UTF-8'}
        command = [str(binary), 'run', '--no-config', '--cwd-mode', 'none',
                   '--cpus', '1', '--memory', '512', '--gpu=' + hex(args.gpu_flags),
                   '--', '/usr/bin/python3', '-u', '-c', GUEST_CLIENT]
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            try:
                output, error = process.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                output, error = process.communicate()
                raise AssertionError('GPU VM timed out: ' + error[-4000:].decode(errors='replace'))
            assert process.returncode == 0 and b'GPU_RENDERER=' in output, (
                f'GPU VM returned {process.returncode}; stdout={output[-4000:]!r}; '
                f'stderr={error[-4000:]!r}')
            print('GPU VM passed: ' + output.decode(errors='replace').strip(), flush=True)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


if __name__ == '__main__':
    main()

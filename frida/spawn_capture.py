#!/usr/bin/env python3
"""
Spawn xhs via frida-server 17.8.2 on port 47042 and inject xhs_capture_pure.js.
Uses the original (unmodified) xhs.apk so libxyass's APK integrity check passes.
"""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'xhs_capture_pure.js')
REMOTE = '127.0.0.1:47042'
TARGET = 'com.xingin.xhs'


def on_msg(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg.get('payload'), flush=True)
    elif msg['type'] == 'error':
        print('[err]', msg.get('description'), flush=True)
        if msg.get('stack'):
            print(msg['stack'], flush=True)


def main():
    print(f'[*] frida {frida.__version__}', flush=True)
    print(f'[*] Remote: {REMOTE}', flush=True)
    print(f'[*] Target: {TARGET}', flush=True)
    print(f'[*] Script: {SCRIPT}', flush=True)

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(REMOTE)
    print(f'[*] Device: {device}', flush=True)
    # Skip enumerate_processes — has a bug in some frida 16 versions where
    # it throws ProcessNotFoundError for 'system_server'. Go directly to spawn.

    # Spawn-attach mode: frida spawns the process and we inject BEFORE the
    # app's main code runs (Application.onCreate). This gives us a full
    # window to install hooks before libxyass loads.
    print(f'[*] Spawning {TARGET}...', flush=True)
    pid = device.spawn([TARGET])
    print(f'[*] Spawned PID: {pid}', flush=True)

    session = device.attach(pid)
    print(f'[*] Attached', flush=True)

    with open(SCRIPT) as f:
        code = f.read()
    script = session.create_script(code)
    script.on('message', on_msg)
    script.load()
    print(f'[*] Script loaded, resuming...', flush=True)

    device.resume(pid)
    print(f'[*] Resumed. Monitoring (60 minutes)...', flush=True)

    for i in range(7200):  # 1h
        time.sleep(0.5)
        if session.is_detached:
            print(f'[!] Session detached after {i * 0.5}s', flush=True)
            break


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[*] Interrupted', flush=True)
    except Exception as e:
        print(f'[FATAL] {e}', flush=True)
        sys.exit(1)

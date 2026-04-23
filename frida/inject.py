#!/usr/bin/env python3
"""
Frida spawn + inject + keep-alive for xhs SSL unpinning.

Usage:
    python3 inject.py                       # xhs
    python3 inject.py com.ss.android.ugc.aweme   # 抖音
"""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(HERE, os.environ.get('XHS_SCRIPT', 'xhs_bypass_all.js'))
TARGET = sys.argv[1] if len(sys.argv) > 1 else 'com.xingin.xhs'


def on_message(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg['payload'], flush=True)
    elif msg['type'] == 'error':
        print('[err]', msg.get('description', msg), flush=True)


def main():
    print(f'[*] Target: {TARGET}', flush=True)
    print(f'[*] Script: {SCRIPT_PATH}', flush=True)

    device = frida.get_usb_device(timeout=5)
    print(f'[*] Device: {device.name}', flush=True)

    pid = device.spawn([TARGET])
    print(f'[*] Spawned PID: {pid}', flush=True)

    session = device.attach(pid)
    with open(SCRIPT_PATH) as f:
        script = session.create_script(f.read())
    script.on('message', on_message)
    script.load()
    print(f'[*] Script loaded, resuming...', flush=True)
    device.resume(pid)

    print(f'[*] Injection active — keep this running while you use the app', flush=True)
    while True:
        time.sleep(5)
        if session.is_detached:
            print('[!] Session detached, exiting', flush=True)
            break


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[*] Interrupted', flush=True)
    except Exception as e:
        print(f'[FATAL] {e}', flush=True)
        sys.exit(1)

#!/usr/bin/env python3
"""Spawn xhs with stealth Frida (renamed server, non-standard port)."""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'native_ssl_bypass.js')
TARGET = sys.argv[1] if len(sys.argv) > 1 else 'com.xingin.xhs'
REMOTE = '127.0.0.1:34471'


def on_msg(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg.get('payload'), flush=True)
    elif msg['type'] == 'error':
        print('[err]', msg.get('description'), flush=True)


def main():
    print(f'[*] Target: {TARGET}', flush=True)
    print(f'[*] Remote frida-server: {REMOTE}', flush=True)
    print(f'[*] Script: {SCRIPT}', flush=True)

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(REMOTE)
    print(f'[*] Device ready: {device}', flush=True)

    pid = device.spawn([TARGET])
    print(f'[*] Spawned PID: {pid}', flush=True)

    session = device.attach(pid)
    with open(SCRIPT) as f:
        script = session.create_script(f.read())
    script.on('message', on_msg)
    script.load()
    device.resume(pid)
    print(f'[*] Resumed. Monitoring for 5 minutes...', flush=True)

    for i in range(60):
        time.sleep(5)
        if session.is_detached:
            print(f'[!] Session detached at {i*5}s', flush=True)
            break
    print('[*] done', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'[FATAL] {e}', flush=True)
        sys.exit(1)

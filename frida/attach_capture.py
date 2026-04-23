#!/usr/bin/env python3
"""
Attach to an already-running xhs process and inject xhs_capture_pure.js.
This avoids the spawn mode timeout issue with zygote signaling. xhs is
launched via adb monkey before running this.
"""
import frida, sys, time, os, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'xhs_capture_pure.js')
REMOTE = '127.0.0.1:47042'
PACKAGE = 'com.xingin.xhs'


def get_xhs_pid():
    try:
        out = subprocess.check_output(['adb', 'shell', 'pidof', PACKAGE],
                                       stderr=subprocess.DEVNULL).decode().strip()
        return int(out) if out else None
    except Exception:
        return None


def on_msg(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg.get('payload'), flush=True)
    elif msg['type'] == 'error':
        print('[err]', msg.get('description'), flush=True)


def main():
    print(f'[*] frida {frida.__version__}', flush=True)
    pid = get_xhs_pid()
    if pid is None:
        print('[!] xhs not running; please launch it first', flush=True)
        sys.exit(1)
    print(f'[*] Found {PACKAGE} PID={pid}', flush=True)

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(REMOTE)
    print(f'[*] Device: {device}', flush=True)

    session = device.attach(pid)
    print(f'[*] Attached to PID {pid}', flush=True)

    with open(SCRIPT) as f:
        code = f.read()
    script = session.create_script(code)
    script.on('message', on_msg)
    script.load()
    print(f'[*] Script loaded, monitoring...', flush=True)

    for i in range(7200):
        time.sleep(0.5)
        if session.is_detached:
            print(f'[!] Session detached after {i * 0.5}s', flush=True)
            break


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'[FATAL] {e}', flush=True)
        sys.exit(1)

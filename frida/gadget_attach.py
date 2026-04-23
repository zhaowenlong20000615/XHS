#!/usr/bin/env python3
"""
Attach Frida to a running xhs gadget (listen mode on 127.0.0.1:27042)
and inject the survivor/bypass script.
"""
import frida, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, os.environ.get('XHS_SCRIPT', 'xhs_survivor.js'))
REMOTE = '127.0.0.1:27042'


def on_msg(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg.get('payload'), flush=True)
    elif msg['type'] == 'error':
        print('[err]', msg.get('description'), flush=True)
        if msg.get('stack'):
            print(msg['stack'], flush=True)


def main():
    print(f'[*] Remote: {REMOTE}', flush=True)
    print(f'[*] Script: {SCRIPT}', flush=True)

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(REMOTE)
    print(f'[*] Device: {device}', flush=True)

    # Gadget 在进程里默认注册自己名字为 'Gadget'
    # attach by name 'Gadget' or by pid 0 for self
    try:
        session = device.attach('Gadget')
    except Exception as e:
        print(f'[*] attach("Gadget") failed: {e}', flush=True)
        # fallback: attach by pid 0 which is the host process
        session = device.attach(0)

    print(f'[*] Attached', flush=True)

    with open(SCRIPT) as f:
        code = f.read()
    script = session.create_script(code)
    script.on('message', on_msg)
    script.load()
    print(f'[*] Script loaded, keeping alive...', flush=True)

    for i in range(1800):
        time.sleep(2)
        if session.is_detached:
            print(f'[!] Detached after {i*2}s', flush=True)
            break


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'[FATAL] {e}', flush=True)
        sys.exit(1)

#!/usr/bin/env python3
"""
Frida runner for trace_tiny_cmds.js.
Writes each cmd invocation to captures/tiny_cmds_<timestamp>.jsonl

Usage:
    python3 trace_tiny_runner.py           # wait for fresh xhs launch
    python3 trace_tiny_runner.py --spawn   # force spawn fresh

Stop with Ctrl-C when you've seen the first sign happen (e.g. /api/v1/cfg/android request).
"""
import frida
import json
import sys
import time
import os

SCRIPT = os.path.join(os.path.dirname(__file__), 'trace_tiny_cmds.js')
OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'lsposed', 'xhs-capture', 'captures')
os.makedirs(OUT_DIR, exist_ok=True)

OUT_FILE = os.path.join(OUT_DIR, f'tiny_cmds_{int(time.time())}.jsonl')
PACKAGE = 'com.xingin.xhs'


def main():
    spawn = '--spawn' in sys.argv
    device = frida.get_usb_device(timeout=5)

    if spawn:
        print(f'[runner] spawning {PACKAGE} ...')
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
    else:
        print(f'[runner] attaching to running {PACKAGE} ...')
        session = device.attach(PACKAGE)
        pid = None

    with open(SCRIPT) as f:
        code = f.read()
    script = session.create_script(code)

    sink = open(OUT_FILE, 'w')
    count = [0]

    def on_msg(msg, data):
        if msg['type'] == 'send':
            payload = msg['payload']
            sink.write(json.dumps(payload) + '\n')
            sink.flush()
            count[0] += 1
            if count[0] % 20 == 0:
                print(f'[runner] captured {count[0]} cmd calls → {OUT_FILE}')
        elif msg['type'] == 'error':
            print('[runner] error:', msg.get('description'))

    script.on('message', on_msg)
    script.load()

    if spawn and pid is not None:
        device.resume(pid)

    print(f'[runner] tracing, output → {OUT_FILE}')
    print('[runner] stop with Ctrl-C when first mua seen.')
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
        print(f'[runner] captured {count[0]} calls total → {OUT_FILE}')


if __name__ == '__main__':
    main()

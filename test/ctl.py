#!/usr/bin/env python3
"""Talk to the hvpn control daemon: ctl.py STATUS | ctl.py NODE START ... | ..."""
import socket
import sys

SOCK = "/var/run/hvpn/control.sock"


def send(cmd, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall((cmd + "\n").encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"END\n"):
            break
    s.close()
    return data.decode().removesuffix("END\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: ctl.py COMMAND [args...]", file=sys.stderr)
        sys.exit(2)
    print(send(" ".join(sys.argv[1:])), end="")

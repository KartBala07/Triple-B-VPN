#!/usr/bin/env python3
"""Install the HermesVPN helper daemon (launchd) and the app bundle. Runs as root."""
import os
import plistlib
import shutil
import socket
import stat
import subprocess
import sys
import time

PREFIX = os.path.dirname(os.path.abspath(__file__))
APP_SRC = os.path.join(PREFIX, "build", "HermesVPN.app")
BIN_SRC = os.path.join(PREFIX, "target", "release", "hvpn")
CTL_SRC = os.path.join(PREFIX, "bin", "hvpnctl")
PLIST_SRC = os.path.join(PREFIX, "deploy", "com.hermes.vpn.plist")
LABEL = "com.hermes.vpn"
PLIST_DST = f"/Library/LaunchDaemons/{LABEL}.plist"
SOCK = "/var/run/hvpn/control.sock"
DAEMON_LOG = "/var/log/hermesvpn-daemon.log"


def run(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"   ! {' '.join(cmd)} -> {r.stderr.strip()}")
    return r


def install_file(src, dst, mode=0o755):
    shutil.copy2(src, dst)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)


def ctl(cmd):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(SOCK)
        s.sendall((cmd + "\n").encode())
        data = s.recv(8192).decode(errors="replace")
        s.close()
        return data
    except OSError:
        return ""


def main():
    if os.geteuid() != 0:
        print("needs root", file=sys.stderr)
        return 1
    if not os.path.isdir(APP_SRC):
        print("app not built — run ./build-app.sh first", file=sys.stderr)
        return 1

    print("== 1/4 binaries")
    os.makedirs("/usr/local/bin", exist_ok=True)
    install_file(BIN_SRC, "/usr/local/bin/hvpn")
    install_file(CTL_SRC, "/usr/local/bin/hvpnctl")
    print("   /usr/local/bin/hvpn, /usr/local/bin/hvpnctl")

    print("== 2/4 stopping any previous helper")
    if os.path.exists(SOCK):
        ctl("STOPALL")
        ctl("QUIT")
        time.sleep(1)
    run(["launchctl", "bootout", f"system/{LABEL}"])
    time.sleep(0.5)
    run(["/usr/local/bin/hvpn", "down"])
    run(["pfctl", "-f", "/etc/pf.conf"])
    run(["sysctl", "-w", "net.inet.ip.forwarding=0"])
    if os.path.exists(SOCK):
        os.unlink(SOCK)

    print("== 3/4 installing helper")
    install_file(PLIST_SRC, PLIST_DST, 0o644)
    open(DAEMON_LOG, "a").close()
    os.chown(DAEMON_LOG, 0, 0)
    boot = run(["launchctl", "bootstrap", "system", PLIST_DST], check=True)
    if boot.returncode != 0:
        print("   bootstrap said:", boot.stderr.strip() or boot.stdout.strip())
    run(["launchctl", "enable", f"system/{LABEL}"])
    for _ in range(40):
        if os.path.exists(SOCK):
            break
        time.sleep(0.25)
    if os.path.exists(SOCK):
        st = os.stat(SOCK)
        print(f"   helper up: socket mode {oct(stat.S_IMODE(st.st_mode))} uid {st.st_uid}:{st.st_gid}")
        print("   ping:", ctl("PING").strip())
    else:
        print("   helper FAILED to start:", file=sys.stderr)
        try:
            print(open(DAEMON_LOG).read()[-800:], file=sys.stderr)
        except OSError:
            pass

    print("== 4/4 app bundle")
    dst_app = "/Applications/HermesVPN.app"
    if os.path.isdir(dst_app):
        shutil.rmtree(dst_app)
    shutil.copytree(APP_SRC, dst_app, symlinks=True)
    for root, dirs, files in os.walk(dst_app):
        os.chown(root, 0, 0)
        for f in files:
            os.chown(os.path.join(root, f), 0, 0)
    run(["xattr", "-dr", "com.apple.quarantine", dst_app])
    print("   " + dst_app)

    print()
    print("installed. open /Applications/HermesVPN.app")
    return 0


if __name__ == "__main__":
    sys.exit(main())

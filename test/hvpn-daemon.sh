#!/bin/bash
# Detached launcher: clears the inherited signal mask (launchd/osascript spawn
# children with SIGINT/SIGTERM blocked) and moves the process into its own
# session so it survives the launching shell and does not catch SIGHUP.
exec python3 -c 'import os,signal,sys
signal.pthread_sigmask(signal.SIG_SETMASK, [])
try:
    os.setsid()
except OSError:
    pass
os.execvp(sys.argv[1], sys.argv[1:])' "$@"

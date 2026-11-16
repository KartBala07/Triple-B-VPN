#!/bin/bash
exec python3 -c 'import os,signal,sys; signal.pthread_sigmask(signal.SIG_SETMASK, []); os.execvp(sys.argv[1], sys.argv[1:])' "$@"

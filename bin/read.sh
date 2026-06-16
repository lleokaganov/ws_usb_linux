#!/bin/bash

clear
set -u

TTY_PORT="/dev/ttyUSB0"
echo "port=${TTY_PORT}"

stty -F "$TTY_PORT" 115200 cs8 -cstopb -parenb -crtscts clocal raw -echo \
    -echoe -echok -echoctl -echoke 2>/dev/null \
    || warn "stty failed (continuing anyway)"

# ---------------------------------------------------------------- e) stream
hdr "Reading $TTY_PORT (Ctrl-C to stop)"
if [ "$HEX_MODE" = 1 ]; then
    # Line-buffered xxd: one row of 16 bytes per line, no buffering delays.
    cat "$TTY_PORT" | xxd &
else
    cat "$TTY_PORT" &
fi
CAT_PID=$!
wait "$CAT_PID"

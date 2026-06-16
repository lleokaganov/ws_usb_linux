#!/bin/bash

clear
set -u

TTY_PORT="/dev/ttyUSB0"
echo "port=${TTY_PORT}"

stty -F "$TTY_PORT" 115200 cs8 -cstopb -parenb -crtscts clocal raw -echo \
    -echoe -echok -echoctl -echoke 2>/dev/null \
    || warn "stty failed (continuing anyway)"

echo "Reading $TTY_PORT (Ctrl-C to stop)"

#cat "$TTY_PORT" | xxd &
cat "$TTY_PORT" &

CAT_PID=$!
wait "$CAT_PID"

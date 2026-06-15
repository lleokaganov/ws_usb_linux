#!/bin/bash
#
# read_wsuart.sh — open the USB-UART device that's plugged into the phone
# (wsusb app) and stream RX bytes to stdout. Live tail.
#
#   1. clean up stale usbws / usbip processes
#   2. open the encrypted tunnel to the phone using the wsusb invite
#   3. attach the remote USB device via vhci → /dev/ttyUSB?
#   4. configure baud (default 115200, raw, no flow control)
#   5. cat /dev/ttyUSB? until Ctrl-C
#   6. detach + kill the tunnel on exit
#
# Usage:
#   ./read_wsuart.sh                # 115200 baud, default invite
#   BAUD=9600 ./read_wsuart.sh
#   INVITE=K0... ./read_wsuart.sh
#   ./read_wsuart.sh --hex          # show bytes as hex (xxd) for binary streams

set -u
cd "$(dirname "$0")"

# ---------------------------------------------------------------- config
INVITE="${INVITE:-K0eNoF-h6c15D3VJ58RHN1UmvxMB83HCESGpMrGOJURCOUewTFO801tTJrwszCkrKYhgN1yeDMJvFbtS_64qyKPnVzYndz}"
USBWS="${USBWS:-/home/opt/Claude/usbws/target/release/usbws}"
PORT="${PORT:-3240}"
BAUD="${BAUD:-115200}"
LIST_TIMEOUT=10
SETTLE=2

# --hex mode pipes the stream through xxd for byte-accurate display.
HEX_MODE=0
if [ "${1:-}" = "--hex" ]; then HEX_MODE=1; fi

# ---------------------------------------------------------------- pretty out
if [ -t 2 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; X=$'\033[0m'
else R=; G=; Y=; B=; X=; fi
hdr()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$X" >&2; }
ok()   { printf '%s✓%s %s\n'  "$G" "$X" "$*" >&2; }
warn() { printf '%s!%s %s\n'  "$Y" "$X" "$*" >&2; }
err()  { printf '%s✗%s %s\n'  "$R" "$X" "$*" >&2; }

USBWS_PID=""
CAT_PID=""
teardown() {
    [ -n "$CAT_PID" ] && kill "$CAT_PID" 2>/dev/null
    for p in $(sudo usbip port 2>/dev/null | grep -oE '^Port [0-9]+' | grep -oE '[0-9]+'); do
        sudo usbip detach -p "$p" >/dev/null 2>&1
    done
    [ -n "$USBWS_PID" ] && kill "$USBWS_PID" 2>/dev/null
    pkill -9 -f "usbws tcp-listen $PORT" 2>/dev/null
    echo >&2
    ok "tunnel torn down"
}
trap teardown EXIT INT TERM
die() { err "$2"; exit "$1"; }

# ---------------------------------------------------------------- a) cleanup
hdr "Cleanup"
sudo pkill -9 -x usbip          2>/dev/null
pkill -9 -f "usbws tcp-listen"  2>/dev/null
sudo modprobe vhci-hcd          2>/dev/null
for p in $(sudo usbip port 2>/dev/null | grep -oE '^Port [0-9]+' | grep -oE '[0-9]+'); do
    sudo usbip detach -p "$p" >/dev/null 2>&1
done
TTY_BEFORE=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | sort -u)
sleep 1

# ---------------------------------------------------------------- b) tunnel
hdr "Tunnel"
[ -x "$USBWS" ] || die 1 "usbws not found: $USBWS"
"$USBWS" tcp-listen "$PORT" --peer "$INVITE" >/tmp/read_wsuart.log 2>&1 &
USBWS_PID=$!
sleep 3
kill -0 "$USBWS_PID" 2>/dev/null \
    || { sed 's/^/    /' /tmp/read_wsuart.log >&2; die 1 "usbws failed (see /tmp/read_wsuart.log)"; }
ok "usbws pid $USBWS_PID → 127.0.0.1:$PORT"

# ---------------------------------------------------------------- c) attach
hdr "Attach"
LIST=$(sudo timeout -k 2 "$LIST_TIMEOUT" usbip list -r 127.0.0.1 2>&1)
BUSID=$(printf '%s\n' "$LIST" | grep -oE '^[[:space:]]*[0-9]+-[0-9.]+:' | head -1 | tr -d ' :')
if [ -z "$BUSID" ]; then
    err "wsusb is not sharing any USB device (in ${LIST_TIMEOUT}s)."
    printf '%s\n' "$LIST" | sed 's/^/    /' >&2
    die 2 "no device"
fi
DEVNAME=$(printf '%s\n' "$LIST" | sed -nE "s/^[[:space:]]*${BUSID}:[[:space:]]*//p" | head -1)
ok "found busid $BUSID — ${DEVNAME:-?}"
sudo usbip attach -r 127.0.0.1 -b "$BUSID" 2>/tmp/read_wsuart_attach.log \
    || { sed 's/^/    /' /tmp/read_wsuart_attach.log >&2; die 3 "usbip attach failed"; }
sleep "$SETTLE"

# ---------------------------------------------------------------- d) tty
TTY_AFTER=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | sort -u)
TTY_PORT=$(comm -13 <(printf '%s\n' "$TTY_BEFORE") <(printf '%s\n' "$TTY_AFTER") | head -1)
[ -n "$TTY_PORT" ] || die 4 "no new /dev/ttyUSB? appeared (check dmesg)"
ok "$TTY_PORT @ $BAUD baud"

stty -F "$TTY_PORT" "$BAUD" cs8 -cstopb -parenb -crtscts clocal raw -echo \
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

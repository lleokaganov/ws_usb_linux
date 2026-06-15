#!/bin/bash
#
# test_wsuart.sh — end-to-end loopback test for a USB-UART device shared from
# the phone (wsusb app) through the ws_server relay.
#
# Plug a USB-UART converter (CH340 / CP2102 / FTDI / cdc-acm) into the phone
# via OTG, short TX↔RX with a jumper, run this. Steps:
#
#   1. clean up stale usbws / usbip processes
#   2. open the encrypted tunnel to the phone using the wsusb invite
#   3. look up the remote USB device, attach it via vhci
#   4. configure the local /dev/ttyUSB? at $BAUD, raw, no flow control
#   5. send a tagged probe string, read it back, compare byte-for-byte
#   6. detach + kill the tunnel
#
# Exit codes:  0 ok · 1 setup · 2 no remote device · 3 attach · 4 no /dev/tty
#              · 5 nothing came back · 6 corrupted echo
#
# Usage:
#   ./test_wsuart.sh                # use defaults
#   BAUD=9600 ./test_wsuart.sh      # different baud
#   INVITE=K0... ./test_wsuart.sh   # override the wsusb invite

clear
set -u
cd "$(dirname "$0")"

# ---------------------------------------------------------------- config
# Wsusb invite — public key-invite, not a secret. If wsusb was reinstalled or
# you tapped "Reset identity" in Settings, paste the new K0… here (or pass via
# $INVITE env var on the command line).
INVITE="${INVITE:-K0eNoF-h6c15D3VJ58RHN1UmvxMB83HCESGpMrGOJURCOUewTFO801tTJrwszCkrKYhgN1yeDMJvFbtS_64qyKPnVzYndz}"
USBWS="${USBWS:-/home/opt/Claude/usbws/target/release/usbws}"
PORT="${PORT:-3240}"
BAUD="${BAUD:-115200}"
LIST_TIMEOUT=10            # seconds to wait for the remote usbip listing
SETTLE=2                   # seconds to let /dev/ttyUSB? appear after attach
READ_WINDOW=4              # seconds the reader stays open

# ---------------------------------------------------------------- pretty out
if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; X=$'\033[0m'
else R=; G=; Y=; B=; X=; fi
hdr()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$X"; }
ok()   { printf '%s✓%s %s\n'  "$G" "$X" "$*"; }
warn() { printf '%s!%s %s\n'  "$Y" "$X" "$*"; }
err()  { printf '%s✗%s %s\n'  "$R" "$X" "$*"; }

USBWS_PID=""
TTY_BEFORE=""
TTY_PORT=""
teardown() {
    # detach every vhci port we attached (lazy: just nuke all of ours)
    for p in $(sudo usbip port 2>/dev/null | grep -oE '^Port [0-9]+' | grep -oE '[0-9]+'); do
        sudo usbip detach -p "$p" >/dev/null 2>&1
    done
    [ -n "$USBWS_PID" ] && kill "$USBWS_PID" 2>/dev/null
    pkill -9 -f "usbws tcp-listen $PORT" 2>/dev/null
}
trap teardown EXIT
die() { err "$2"; exit "$1"; }

# ---------------------------------------------------------------- a) cleanup
hdr "a) Cleanup stale processes"
sudo pkill -9 -x usbip          2>/dev/null
pkill -9 -f "usbws tcp-listen"  2>/dev/null
sudo modprobe vhci-hcd          2>/dev/null
for p in $(sudo usbip port 2>/dev/null | grep -oE '^Port [0-9]+' | grep -oE '[0-9]+'); do
    sudo usbip detach -p "$p" >/dev/null 2>&1
done
# Remember which tty* devices exist BEFORE attach, so we can spot the new one.
TTY_BEFORE=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | sort -u)
sleep 1
ok "cleaned up"

# ---------------------------------------------------------------- tunnel
hdr "b) Encrypted tunnel to phone (wsusb) via relay"
[ -x "$USBWS" ] || die 1 "usbws not found / not executable: $USBWS"
"$USBWS" tcp-listen "$PORT" --peer "$INVITE" >/tmp/test_wsuart.log 2>&1 &
USBWS_PID=$!
sleep 3
if kill -0 "$USBWS_PID" 2>/dev/null; then
    ok "usbws tunnel up (pid $USBWS_PID → 127.0.0.1:$PORT)"
else
    sed 's/^/    /' /tmp/test_wsuart.log
    die 1 "usbws failed to start (see /tmp/test_wsuart.log)"
fi

# ---------------------------------------------------------------- c) device?
hdr "c) Remote USB-UART (shared from the phone)"
LIST=$(sudo timeout -k 2 "$LIST_TIMEOUT" usbip list -r 127.0.0.1 2>&1)
BUSID=$(printf '%s\n' "$LIST" | grep -oE '^[[:space:]]*[0-9]+-[0-9.]+:' | head -1 | tr -d ' :')
if [ -z "$BUSID" ]; then
    err "No USB device exported by wsusb (in ${LIST_TIMEOUT}s)."
    warn "Phone offline or wsusb not sharing. Keep wsusb in foreground,"
    warn "disable battery optimization, plug the UART converter into the phone."
    printf '%s\n' "$LIST" | sed 's/^/    /'
    die 2 "remote device unavailable"
fi
DEVNAME=$(printf '%s\n' "$LIST" | sed -nE "s/^[[:space:]]*${BUSID}:[[:space:]]*//p" | head -1)
ok "Remote device present — busid ${BUSID}"
printf '    %s\n' "${DEVNAME:-?}"

# ---------------------------------------------------------------- attach
sudo usbip attach -r 127.0.0.1 -b "$BUSID" 2>/tmp/test_wsuart_attach.log \
    || { sed 's/^/    /' /tmp/test_wsuart_attach.log; die 3 "usbip attach failed"; }
sleep "$SETTLE"
ok "attached to local vhci"

# ---------------------------------------------------------------- d) tty?
hdr "d) Local serial port that appeared"
TTY_AFTER=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | sort -u)
TTY_PORT=$(comm -13 <(printf '%s\n' "$TTY_BEFORE") <(printf '%s\n' "$TTY_AFTER") | head -1)
if [ -z "$TTY_PORT" ]; then
    err "No new /dev/ttyUSB? or /dev/ttyACM? device appeared after attach."
    warn "dmesg | tail -20 might explain why (ch341 / cdc_acm load failure)."
    die 4 "no tty"
fi
ok "$TTY_PORT"

# Configure: $BAUD, 8N1, raw, no flow control. clocal so open() doesn't block.
stty -F "$TTY_PORT" "$BAUD" cs8 -cstopb -parenb -crtscts clocal raw -echo \
    -echoe -echok -echoctl -echoke 2>/dev/null \
    || warn "stty failed (continuing anyway)"

# ---------------------------------------------------------------- e) loopback
hdr "e) Loopback probe (TX↔RX jumper required)"
PROBE="wsusb-loopback-$(date +%H%M%S)-$$"
RX_FILE=$(mktemp /tmp/wsuart_rx.XXXXXX)

# Open a reader first, wait a beat for it to be listening, then send.
( timeout "$READ_WINDOW" cat "$TTY_PORT" > "$RX_FILE" ) &
RX_PID=$!
sleep 1
printf '%s\n' "$PROBE" > "$TTY_PORT"
wait "$RX_PID" 2>/dev/null

if [ ! -s "$RX_FILE" ]; then
    err "Nothing came back in ${READ_WINDOW}s."
    warn "Check: TX-RX jumper actually wired? same converter that worked locally?"
    warn "dmesg tail:"
    sudo dmesg | tail -10 | sed 's/^/    /'
    die 5 "no echo"
fi

# Strip trailing CR/LF, compare to the probe we sent.
RX=$(tr -d '\r\n' < "$RX_FILE")
if [ "$RX" = "$PROBE" ]; then
    ok "Echo OK — ${#PROBE} bytes round-trip"
    printf '    sent : %s\n' "$PROBE"
    printf '    got  : %s\n' "$RX"
else
    err "Echo CORRUPTED."
    printf '    sent : %s\n' "$PROBE"
    printf '    got  : %s\n' "$RX"
    printf '    hex  : '
    xxd "$RX_FILE" | head -2 | sed 's/^/           /'
    die 6 "corrupted"
fi

hdr "Result"
ok "wsusb UART round-trip works at $BAUD baud through the relay"

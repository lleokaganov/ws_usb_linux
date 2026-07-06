# ws_usb_linux

> The Linux side of the remote-USB bridge. The CLI binary is still named
> `usbws` (Cargo package unchanged); the Android gate app lives separately in
> the `wsusb` project.

Tunnel a serial port **or a TCP port** between two machines over the encrypted
ws_server relay (protocol v2). Serial covers `/dev/ttyUSB*` / `/dev/ttyACM*`;
the TCP tunnel forwards an arbitrary TCP port (e.g. usbip's 3240, so USB
programmers can be shared via standard `usbip`).

The relay only ever sees ciphertext: traffic is end-to-end encrypted between
the two peers (X25519 + Ed25519 + XChaCha20-Poly1305), reusing the exact wire
format of `telefon_lleo/wschat`.

## How it works

```
  real device                                              virtual port
  /dev/ttyUSB0                                             /dev/pts/N
       │                                                        │
   [ usbws share ] ──enc──▶ ws.lleo.me relay ──enc──▶ [ usbws attach ]
       │                                                        │
       ◀────────────────────── bidirectional ──────────────────┘
```

- The machine with the hardware runs `share` and opens the real serial device.
- The remote machine runs `attach`, which creates a local PTY (a virtual
  serial port at `/dev/pts/N`). Point a terminal or flasher at that path.

## Identity & authorization

- Each machine has a **persistent** keypair in `~/.config/usbws/identity`
  (mode 0600, auto-created on first run).
- Authorization is **trust-by-key**: each side is told the other's invite code
  (`K0...`) and connects automatically. No interactive confirmation (headless).

## CLI

```
usbws keygen
    Print this machine's id + invite ("K0..."), then exit.

usbws share <serial-dev> --peer K0... [--baud N]
    Bridge a real serial device (default 115200 baud, 8N1, raw, no flow ctrl).
    The peer comes from --peer or USBWS_PEER (the positional is the device).

usbws attach <peer-invite> [--link PATH] [--baud N]
    Create a local PTY bridged to the peer. The positional IS the peer invite.
    --link makes a stable symlink (e.g. /tmp/ttyV0 -> /dev/pts/N).

usbws tcp-listen <localport> --peer K0...
    "Home" side. Listen on 127.0.0.1:<localport>. Each accepted connection is
    tunneled to the peer, which dials its tcp-connect target. Peer comes from
    --peer or USBWS_PEER (the positional is the local port).

usbws tcp-connect <host:port> --peer K0...
    "Gate" side. On the peer's request, dial host:port and proxy bytes back.
    Peer comes from --peer or USBWS_PEER (the positional is the target).
```

### TCP tunnel multiplexing

Several TCP connections share one peer link via a 1-byte connection id
(`conn_id`), so protocols that open more than one socket (like usbip) work
through a single tunnel. The `tcp-listen` side allocates a `conn_id` per accept
and sends `CMD_TCP_OPEN`; bytes flow as `CMD_TCP_DATA [conn_id][bytes]`;
`CMD_TCP_CLOSE [conn_id]` signals one direction's end (TCP half-close is
honored — the opposite direction keeps flowing until it too ends).

### Symmetry

Both sides must know the peer's invite. To keep the CLI unambiguous:

- `share` positional = the **device**; peer is `--peer K0...` (or `USBWS_PEER`).
- `attach` positional = the **peer invite** (most ergonomic); `--peer` and
  `USBWS_PEER` also accepted.

## Env overrides

| Var                  | Default                          |
|----------------------|----------------------------------|
| `USBWS_WS_URL`       | `ws://ws.lleo.me/api0`           |
| `USBWS_SERVER_X_PUB` | Pi ws.lleo.me X25519 pubkey      |
| `USBWS_SERVER_ED_PUB`| Pi ws.lleo.me Ed25519 pubkey     |
| `USBWS_PEER`         | peer invite (alt to flag/pos)    |
| `USBWS_NICK`         | `usbws`                          |
| `USBWS_IDENTITY`     | `~/.config/usbws/identity`       |

## Quick start (two machines)

```
# machine A (hardware here)
usbws keygen                       # note invite A
usbws share /dev/ttyUSB0 --peer <invite-B>

# machine B (remote)
usbws keygen                       # note invite B
usbws attach <invite-A> --link /tmp/ttyV0
# -> prints /dev/pts/N ; use /tmp/ttyV0 with screen/picocom/esptool
screen /tmp/ttyV0 115200
```

## Local loopback test (one machine)

```
# two identities
USBWS_IDENTITY=/tmp/idA usbws keygen   # -> invite A
USBWS_IDENTITY=/tmp/idB usbws keygen   # -> invite B

# a fake serial device pair
socat -d -d pty,raw,echo=0 pty,raw,echo=0   # prints /dev/pts/X and /dev/pts/Y

# bridge them
USBWS_IDENTITY=/tmp/idA usbws share /dev/pts/X --peer <invite-B> &
USBWS_IDENTITY=/tmp/idB usbws attach <invite-A> --link /tmp/ttyV0 &
# attach prints /dev/pts/Z

# now bytes written to /dev/pts/Y appear on /dev/pts/Z and vice versa
printf 'hello\n' > /dev/pts/Y
cat /tmp/ttyV0
```

## TCP tunnel test (one machine, via the relay)

```
USBWS_IDENTITY=/tmp/idL usbws keygen   # -> invite L (listen / home side)
USBWS_IDENTITY=/tmp/idC usbws keygen   # -> invite C (connect / gate side)

# echo server standing in for the real service (e.g. usbipd)
socat TCP-LISTEN:9000,reuseaddr,fork EXEC:/bin/cat &

# gate side dials the echo server; its peer is the listen side
USBWS_IDENTITY=/tmp/idC usbws tcp-connect 127.0.0.1:9000 --peer <invite-L> &

# home side listens on 9001; its peer is the connect side
USBWS_IDENTITY=/tmp/idL usbws tcp-listen 9001 --peer <invite-C> &

# a client through the tunnel: bytes echo back
ncat 127.0.0.1 9001        # type a line -> it comes back
```

## usbip over the TCP tunnel (sharing a USB programmer)

```
# --- gate machine (programmer plugged in here) ---
sudo modprobe usbip-host
sudo usbipd -D                      # usbipd listens on 127.0.0.1:3240
usbip list -l                       # find the busid, e.g. 1-1.4
sudo usbip bind -b 1-1.4
usbws tcp-connect 127.0.0.1:3240 --peer <invite-home> &

# --- home machine (where you want the device) ---
sudo modprobe vhci-hcd
usbws tcp-listen 3240 --peer <invite-gate> &
# usbip talks to the local tunnel as if usbipd were on this host:
usbip list -r 127.0.0.1
sudo usbip attach -r 127.0.0.1 -b 1-1.4
# the device now appears locally; detach with: sudo usbip detach -p 00
```

## Build

```
cargo build --release   # -> target/release/usbws
```

`serialport` is built without default features (no `libudev` dependency) since
ports are opened by path, never enumerated.

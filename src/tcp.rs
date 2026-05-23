//! TCP port-forward tunnel over the encrypted relay (protocol v2).
//!
//! This rides on the same peer channel as the serial bridge, but instead of a
//! single byte stream it multiplexes several TCP connections over one peer link
//! using a 1-byte connection id (conn_id). That lets a protocol like usbip —
//! which may open more than one socket — work through a single tunnel.
//!
//! Roles:
//!   `tcp-listen <localport>`  — the "home" side (where the usbip client runs).
//!       Listens on 127.0.0.1:<localport>. Each accepted connection gets a
//!       fresh conn_id, sends CMD_TCP_OPEN to the peer, then proxies bytes as
//!       CMD_TCP_DATA and tears down with CMD_TCP_CLOSE.
//!   `tcp-connect <host:port>` — the "gate" side (where usbipd / the real
//!       service runs). On CMD_TCP_OPEN it dials the fixed host:port, then
//!       proxies bytes the same way.
//!
//! Wire (peer→peer payload, inside the v2 envelope):
//!   CMD_TCP_OPEN  [conn_id]
//!   CMD_TCP_DATA  [conn_id][bytes...]
//!   CMD_TCP_CLOSE [conn_id]
//!
//! Architecture: one relay session task owns the websocket. Per-connection
//! socket tasks never touch the ws sink directly (it isn't cloneable); they push
//! ready-to-send peer frames into a single `out` mpsc channel that the session
//! loop drains onto the wire. Incoming peer DATA is routed to the matching
//! connection's writer channel via a shared conn map. Both channels are bounded,
//! which gives end-to-end backpressure without extra machinery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::x25519;

use crate::authorized;
use crate::idfile;
use crate::proto::{
    build_peer_frame, decode_intro_from, decode_server_frame, derive_session, make_qr, pack_inner,
    verify_and_decrypt, xor_header, Identity, Peer, CMD_INTRO_FROM, CMD_TCP_CLOSE, CMD_TCP_DATA,
    CMD_TCP_OPEN,
};
use crate::relay::{self, Relay};

/// Max bytes per CMD_TCP_DATA frame read from a socket. The v2 envelope has
/// fixed overhead; 16 KiB chunks keep frames comfortable and latency low.
const READ_CHUNK: usize = 16 * 1024;

/// Bounded capacity for the outbound (→ relay) and per-connection (→ socket)
/// queues. Bounded = backpressure: a slow consumer eventually stalls its
/// producer instead of growing memory without limit.
const OUT_QUEUE: usize = 512;
const CONN_QUEUE: usize = 256;

/// A peer frame ready to be sent on the websocket.
type OutFrame = Message;

/// A message to a connection's socket-writer task.
enum WrMsg {
    /// Bytes to write to the socket.
    Data(Vec<u8>),
    /// Half-close: shut the socket's write side but keep the read side alive
    /// (the peer's read side ended, but it may still send us data).
    Shutdown,
}

/// conn_id → channel that feeds the bytes destined for that connection's socket.
type ConnMap = Arc<Mutex<HashMap<u8, mpsc::Sender<WrMsg>>>>;

/// Shared context passed to per-connection tasks.
struct Ctx {
    me: Identity,
    peer: Peer,
    k_c2s: [u8; 32],
    out: mpsc::Sender<OutFrame>,
    conns: ConnMap,
}

impl Ctx {
    /// Build a peer-routed frame for `(cmd, body)` and hand it to the out queue.
    /// Returns false if the session is gone (out channel closed).
    async fn send_peer(&self, cmd: u8, body: &[u8]) -> bool {
        let frame = build_peer_frame(
            &self.me,
            &self.peer.x_pub,
            &self.peer.id,
            &self.k_c2s,
            &pack_inner(0, cmd, body),
        );
        self.out.send(Message::Binary(frame)).await.is_ok()
    }
}

// ============================== public entry points ==============================

/// `tcp-listen`: accept local TCP connections and tunnel each to the peer.
pub async fn run_tcp_listen(port: u16, peer: Peer, nick: &str) -> anyhow::Result<()> {
    let (me, created) = idfile::load_or_create()?;
    if created {
        eprintln!("[usbws] created identity at {}", idfile::identity_path().display());
    }

    let bind = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;

    eprintln!(
        "[usbws] tcp-listen {} me={} → peer={} ({})",
        bind,
        hex::encode(me.id),
        hex::encode(peer.id),
        peer.nick
    );
    eprintln!("[usbws] my invite: {}", make_qr(&me, nick));

    let (ctx, out_rx, k_s2c) = build_ctx(me, peer);

    // Acceptor task: allocate conn_id, register a socket-writer channel, spawn
    // the socket reader, and tell the peer to open its side.
    let acc_ctx = ctx.clone();
    tokio::spawn(async move {
        // conn_id is allocated round-robin, skipping ids still in use.
        let mut next_id: u8 = 0;
        loop {
            let (sock, _addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[usbws] accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let conn_id = match alloc_conn_id(&acc_ctx.conns, &mut next_id).await {
                Some(id) => id,
                None => {
                    eprintln!("[usbws] all 256 conn ids in use; dropping connection");
                    continue;
                }
            };
            // Tell the peer to open its outbound socket *before* spawning the
            // reader, so OPEN always precedes any DATA for this conn_id.
            if !acc_ctx.send_peer(CMD_TCP_OPEN, &[conn_id]).await {
                break; // session gone
            }
            spawn_connection(acc_ctx.clone(), conn_id, sock).await;
            eprintln!("[usbws] conn {conn_id}: opened (local accept)");
        }
    });

    session_loop(ctx, out_rx, &k_s2c, nick, None).await
}

/// `tcp-connect`: on the peer's request, dial a fixed host:port and proxy bytes.
pub async fn run_tcp_connect(target: &str, peer: Peer, nick: &str) -> anyhow::Result<()> {
    let (me, created) = idfile::load_or_create()?;
    if created {
        eprintln!("[usbws] created identity at {}", idfile::identity_path().display());
    }

    // Validate the target eagerly so a typo fails fast rather than on first OPEN.
    if target.rsplit_once(':').is_none() {
        anyhow::bail!("target must be host:port (got {target:?})");
    }

    eprintln!(
        "[usbws] tcp-connect → {} me={} ← peer={} ({})",
        target,
        hex::encode(me.id),
        hex::encode(peer.id),
        peer.nick
    );
    eprintln!("[usbws] my invite: {}", make_qr(&me, nick));

    let (ctx, out_rx, k_s2c) = build_ctx(me, peer);
    session_loop(ctx, out_rx, &k_s2c, nick, Some(target.to_string())).await
}

// ============================== relay session ==============================

/// Build the shared context, out queue, and session keys in one place.
/// Returns (ctx, out receiver for the session loop, server→client key).
fn build_ctx(me: Identity, peer: Peer) -> (Arc<Ctx>, mpsc::Receiver<OutFrame>, [u8; 32]) {
    let relay = Relay::from_env();
    let shared = x25519(me.x_priv, relay.server_x_pub);
    let (k_c2s, k_s2c) = derive_session(&shared);
    let conns: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(OUT_QUEUE);
    let ctx = Arc::new(Ctx { me, peer, k_c2s, out: out_tx, conns });
    (ctx, out_rx, k_s2c)
}

/// The shared relay event loop: own the websocket, drain the out queue onto it,
/// and route incoming peer frames. Reconnects on failure (the tunnel survives
/// relay restarts; individual TCP connections may drop and be reopened by the
/// upper protocol).
async fn session_loop(
    ctx: Arc<Ctx>,
    mut out_rx: mpsc::Receiver<OutFrame>,
    k_s2c: &[u8; 32],
    nick: &str,
    dial_target: Option<String>,
) -> anyhow::Result<()> {
    let relay = Relay::from_env();
    let mut seq: u16 = 1;

    'reconnect: loop {
        let mut ws = match relay::connect_and_handshake(&relay, &ctx.me, k_s2c).await {
            Some(ws) => ws,
            None => {
                eprintln!("[usbws] relay unavailable; retry in 5s");
                tokio::select! {
                    _ = relay::backoff(5) => continue 'reconnect,
                    _ = tokio::signal::ctrl_c() => break 'reconnect,
                }
            }
        };
        eprintln!("[usbws] relay connected; introducing self to peer…");
        seq = relay::introduce_and_subscribe(
            &mut ws, &ctx.me, &ctx.peer, nick, &relay, &ctx.k_c2s, seq,
        )
        .await;
        eprintln!("[usbws] tunnel ready");

        loop {
            tokio::select! {
                // Incoming from the relay → route to a connection.
                msg = ws.next() => {
                    match msg {
                        Some(Ok(Message::Binary(b))) => {
                            handle_incoming(&ctx, k_s2c, &b, &dial_target).await;
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = ws.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => {
                            eprintln!("[usbws] relay closed; reconnecting in 3s");
                            break;
                        }
                        Some(Err(e)) => { eprintln!("[usbws] ws error: {e}; reconnecting in 3s"); break; }
                        _ => {}
                    }
                }
                // Outbound frames produced by socket tasks → onto the wire.
                frame = out_rx.recv() => {
                    match frame {
                        Some(f) => {
                            if ws.send(f).await.is_err() {
                                eprintln!("[usbws] send failed; reconnecting in 3s");
                                break;
                            }
                        }
                        None => {
                            // All senders dropped — should not happen while ctx
                            // lives, but exit cleanly if it does.
                            eprintln!("[usbws] out channel closed; exiting");
                            let _ = ws.close(None).await;
                            break 'reconnect;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => { let _ = ws.close(None).await; break 'reconnect; }
            }
        }
        let _ = ws.close(None).await;
        relay::backoff(3).await;
    }
    Ok(())
}

/// Decrypt one relay frame and act on the TCP command it carries.
async fn handle_incoming(
    ctx: &Arc<Ctx>,
    k_s2c: &[u8; 32],
    frame: &[u8],
    dial_target: &Option<String>,
) {
    if frame.len() < 8 + 24 + 16 + 64 {
        return;
    }
    let nonce_24: [u8; 24] = frame[8..32].try_into().unwrap();
    let mut header: [u8; 8] = frame[..8].try_into().unwrap();
    xor_header(k_s2c, &nonce_24, &mut header);
    if header == [0u8; 8] {
        // Server-bound frame (PEER_ONLINE etc.); nothing to do for the tunnel.
        return;
    }

    let Some(inner) =
        verify_and_decrypt(&frame[8..], &ctx.me.x_priv, &ctx.peer.x_pub, &ctx.peer.ed_pub)
    else {
        return;
    };
    if inner.len() < 3 {
        return;
    }
    let cmd = inner[2];
    let body = &inner[3..];
    if body.is_empty() {
        return; // every TCP command has at least a conn_id
    }
    let conn_id = body[0];

    match cmd {
        CMD_TCP_OPEN => {
            // Only the connect side acts on OPEN (it has a dial target). The
            // listen side allocated the id locally and ignores echoes.
            let Some(target) = dial_target.clone() else { return };
            open_outbound(ctx.clone(), conn_id, target).await;
        }
        CMD_TCP_DATA => {
            let payload = &body[1..];
            if payload.is_empty() {
                return;
            }
            // Route to the connection's writer. Hold the lock only to clone the
            // sender, then await the send outside the lock to avoid contention.
            let tx = ctx.conns.lock().await.get(&conn_id).cloned();
            if let Some(tx) = tx {
                // If the socket writer is gone, drop + notify peer to stop.
                if tx.send(WrMsg::Data(payload.to_vec())).await.is_err() {
                    ctx.conns.lock().await.remove(&conn_id);
                    let _ = ctx.send_peer(CMD_TCP_CLOSE, &[conn_id]).await;
                }
            }
            // Unknown conn_id: silently drop (peer raced past a CLOSE).
        }
        CMD_TCP_CLOSE => {
            // The peer's read side ended: shut *our* socket's write half but keep
            // reading, so the opposite direction survives (TCP half-close). The
            // writer task removes the conn entry once it has shut down.
            let tx = ctx.conns.lock().await.get(&conn_id).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(WrMsg::Shutdown).await;
            }
            eprintln!("[usbws] conn {conn_id}: peer closed write side");
        }
        _ => {}
    }
}

// ============================== per-connection plumbing ==============================

/// Dial the fixed target and register the resulting socket under `conn_id`.
/// Used by the tcp-connect side when it receives CMD_TCP_OPEN.
async fn open_outbound(ctx: Arc<Ctx>, conn_id: u8, target: String) {
    match TcpStream::connect(&target).await {
        Ok(sock) => {
            spawn_connection(ctx.clone(), conn_id, sock).await;
            eprintln!("[usbws] conn {conn_id}: dialed {target}");
        }
        Err(e) => {
            eprintln!("[usbws] conn {conn_id}: dial {target} failed: {e}");
            // Tell the peer the connection could not be established.
            let _ = ctx.send_peer(CMD_TCP_CLOSE, &[conn_id]).await;
        }
    }
}

/// Register a socket under `conn_id` and start its two halves:
///   - reader: socket → peer (CMD_TCP_DATA), then CMD_TCP_CLOSE on EOF/error;
///   - writer: peer bytes (from the conn channel) → socket.
async fn spawn_connection(ctx: Arc<Ctx>, conn_id: u8, sock: TcpStream) {
    let (sock_tx, mut sock_rx) = mpsc::channel::<WrMsg>(CONN_QUEUE);
    ctx.conns.lock().await.insert(conn_id, sock_tx);

    let (mut rd, mut wr) = sock.into_split();

    // Writer half: peer → socket. Ends on Shutdown, channel close, or write error.
    let conns_w = ctx.conns.clone();
    tokio::spawn(async move {
        while let Some(msg) = sock_rx.recv().await {
            match msg {
                WrMsg::Data(bytes) => {
                    if wr.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                WrMsg::Shutdown => break,
            }
        }
        // Shut the socket's write half. The reader half keeps running until the
        // socket's read direction also ends, so half-open flows survive.
        let _ = wr.shutdown().await;
        // The writer is the entry's owner: once it exits, drop the map entry so
        // further DATA for this conn_id is recognized as stale.
        conns_w.lock().await.remove(&conn_id);
    });

    // Reader half: socket → peer.
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    // Prefix the conn_id, then ship as CMD_TCP_DATA.
                    let mut body = Vec::with_capacity(1 + n);
                    body.push(conn_id);
                    body.extend_from_slice(&buf[..n]);
                    if !ctx.send_peer(CMD_TCP_DATA, &body).await {
                        break; // session gone
                    }
                }
                Err(_) => break,
            }
        }
        // Our socket's read side ended (EOF/error). Tell the peer to stop writing
        // to its side (CMD_TCP_CLOSE = "my read side is done"). We do NOT remove
        // the conn entry here: our writer half may still be delivering peer data
        // until the peer's read side also ends. The writer owns entry removal.
        let _ = ctx.send_peer(CMD_TCP_CLOSE, &[conn_id]).await;
        eprintln!("[usbws] conn {conn_id}: local read side ended");
    });
}

/// Allocate a free conn_id round-robin from `*next`, skipping ids still mapped.
/// Returns None only if all 256 ids are currently in use.
async fn alloc_conn_id(conns: &ConnMap, next: &mut u8) -> Option<u8> {
    let map = conns.lock().await;
    for _ in 0..=u8::MAX {
        let id = *next;
        *next = next.wrapping_add(1);
        if !map.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

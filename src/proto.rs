//! Protocol v2 crypto + framing for ws_server.
//!
//! Copied and adapted from telefon_lleo/wschat. The wire format is identical
//! to wschat; only the application payload differs (CMD_SERIAL_DATA instead of
//! CMD_TEXT). Keeping this in one module makes the divergence from wschat
//! explicit and easy to audit.

use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::x25519;

pub const PROTOCOL_VERSION: u8 = 2;
pub const QR_PREFIX: &str = "K0";

pub const CMD_HANDSHAKE_REQUEST: u8 = 0x01;
pub const CMD_HANDSHAKE_OK: u8 = 0x02;
/// Raw serial bytes carried peer→peer. usbws-specific (wschat used 0x20 TEXT).
/// Only referenced by the serial bridge; allow it to be unused in tcp-only
/// (Android) builds so the protocol definition stays complete here.
#[allow(dead_code)]
pub const CMD_SERIAL_DATA: u8 = 0x30;
/// TCP tunnel commands (usbws-specific). A `tcp-listen` side accepts local TCP
/// connections and tells the peer to open a matching outbound connection; a
/// `tcp-connect` side dials a fixed host:port on demand. Bytes are framed with
/// a 1-byte connection id so several TCP connections can share one peer link
/// (e.g. usbip may open more than one socket).
///   CMD_TCP_OPEN  body: [conn_id:1]
///   CMD_TCP_DATA  body: [conn_id:1][bytes...]
///   CMD_TCP_CLOSE body: [conn_id:1]
pub const CMD_TCP_OPEN: u8 = 0x32;
pub const CMD_TCP_DATA: u8 = 0x33;
pub const CMD_TCP_CLOSE: u8 = 0x34;
pub const CMD_SUBSCRIBE: u8 = 0x40;
/// Server-originated "peer is online" signal. Only inspected by the serial
/// bridge; allow it to be unused in tcp-only (Android) builds.
#[allow(dead_code)]
pub const CMD_PEER_ONLINE: u8 = 0x42;
pub const CMD_INTRODUCE: u8 = 0x46;
/// Server→client: "here are <sender>'s public keys + nick". Emitted by the
/// relay when some other party sends a CMD_INTRODUCE targeting us. The body is
/// [sender_x_pub:32][sender_ed_pub:32][nick_utf8...]. This is how the receiver
/// learns an initiator's identity *without* having its invite up front — the
/// foundation of capability "accept-incoming" mode. The relay fills the keys
/// from the sender's verified session, so the introduction cannot be forged.
pub const CMD_INTRO_FROM: u8 = 0x47;

// ============================ identity / crypto ============================

#[derive(Clone)]
pub struct Identity {
    pub x_priv: [u8; 32],
    pub x_pub: [u8; 32],
    pub ed: SigningKey,
    pub ed_pub: VerifyingKey,
    pub id: [u8; 8],
}

impl Identity {
    pub fn from_seeds(x_seed: [u8; 32], ed_seed: [u8; 32]) -> Self {
        let mut x_priv = x_seed;
        x_priv[0] &= 248;
        x_priv[31] &= 127;
        x_priv[31] |= 64;
        let x_pub = x25519(x_priv, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ed = SigningKey::from_bytes(&ed_seed);
        let ed_pub = ed.verifying_key();
        let mut id = [0u8; 8];
        id.copy_from_slice(&x_pub[..8]);
        Self { x_priv, x_pub, ed, ed_pub, id }
    }
}

fn fresh_nonce_24() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}

fn aead_encrypt(shared: &[u8; 32], nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(Key::from_slice(shared))
        .encrypt(XNonce::from_slice(nonce), plain)
        .expect("aead encrypt")
}

fn aead_decrypt(shared: &[u8; 32], nonce: &[u8; 24], ct: &[u8]) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(Key::from_slice(shared))
        .decrypt(XNonce::from_slice(nonce), ct)
        .ok()
}

pub fn xor_header(key: &[u8; 32], nonce_24: &[u8; 24], h: &mut [u8; 8]) {
    let nonce12: [u8; 12] = nonce_24[..12].try_into().unwrap();
    let mut cipher = ChaCha20::new(key.into(), &nonce12.into());
    cipher.apply_keystream(h);
}

pub fn derive_session(shared: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let k_c2s = blake3::derive_key("ws.lleo.me v2 route c2s", shared);
    let k_s2c = blake3::derive_key("ws.lleo.me v2 route s2c", shared);
    (k_c2s, k_s2c)
}

pub fn pack_inner(message_id: u16, cmd: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + body.len());
    v.extend_from_slice(&message_id.to_le_bytes());
    v.push(cmd);
    v.extend_from_slice(body);
    v
}

pub fn encrypt_and_sign(
    plain: &[u8],
    my_x_priv: &[u8; 32],
    my_ed: &SigningKey,
    their_x_pub: &[u8; 32],
) -> Vec<u8> {
    let nonce = fresh_nonce_24();
    let shared = x25519(*my_x_priv, *their_x_pub);
    let ct = aead_encrypt(&shared, &nonce, plain);
    let mut packet = Vec::with_capacity(24 + ct.len() + 64);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ct);
    let sig = my_ed.sign(&packet).to_bytes();
    packet.extend_from_slice(&sig);
    packet
}

pub fn verify_and_decrypt(
    packet: &[u8],
    my_x_priv: &[u8; 32],
    their_x_pub: &[u8; 32],
    their_ed_pub: &VerifyingKey,
) -> Option<Vec<u8>> {
    if packet.len() < 24 + 16 + 64 {
        return None;
    }
    let (nc, sig) = packet.split_at(packet.len() - 64);
    let sig: &[u8; 64] = sig.try_into().ok()?;
    if their_ed_pub.verify(nc, &Signature::from_bytes(sig)).is_err() {
        return None;
    }
    let nonce: &[u8; 24] = nc[..24].try_into().ok()?;
    let ct = &nc[24..];
    let shared = x25519(*my_x_priv, *their_x_pub);
    aead_decrypt(&shared, nonce, ct)
}

pub fn build_handshake_request(me: &Identity, server_x_pub: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    body.extend_from_slice(me.ed_pub.as_bytes());
    body.push(PROTOCOL_VERSION);
    let inner = pack_inner(0, CMD_HANDSHAKE_REQUEST, &body);
    let packet = encrypt_and_sign(&inner, &me.x_priv, &me.ed, server_x_pub);
    let mut frame = Vec::with_capacity(32 + packet.len());
    frame.extend_from_slice(&me.x_pub);
    frame.extend_from_slice(&packet);
    frame
}

/// Build a peer-routed frame: [header = peer_id XOR k_c2s][encrypted packet].
pub fn build_peer_frame(
    me: &Identity,
    peer_x_pub: &[u8; 32],
    peer_id: &[u8; 8],
    k_c2s: &[u8; 32],
    inner: &[u8],
) -> Vec<u8> {
    let packet = encrypt_and_sign(inner, &me.x_priv, &me.ed, peer_x_pub);
    let nonce_24: [u8; 24] = packet[..24].try_into().unwrap();
    let mut header = *peer_id;
    xor_header(k_c2s, &nonce_24, &mut header);
    let mut frame = Vec::with_capacity(8 + packet.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&packet);
    frame
}

/// Build a server-routed frame (header XORs to zero on the server side).
pub fn build_server_bound(
    me: &Identity,
    server_x_pub: &[u8; 32],
    k_c2s: &[u8; 32],
    inner: &[u8],
) -> Vec<u8> {
    let packet = encrypt_and_sign(inner, &me.x_priv, &me.ed, server_x_pub);
    let nonce_24: [u8; 24] = packet[..24].try_into().unwrap();
    let mut header = [0u8; 8];
    xor_header(k_c2s, &nonce_24, &mut header);
    let mut frame = Vec::with_capacity(8 + packet.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&packet);
    frame
}

pub fn decode_server_frame(
    frame: &[u8],
    k_s2c: &[u8; 32],
    my_x_priv: &[u8; 32],
    server_x_pub: &[u8; 32],
    server_ed: &VerifyingKey,
) -> Option<Vec<u8>> {
    if frame.len() < 8 + 24 + 16 + 64 {
        return None;
    }
    let nonce_24: [u8; 24] = frame[8..32].try_into().ok()?;
    let mut header: [u8; 8] = frame[..8].try_into().ok()?;
    xor_header(k_s2c, &nonce_24, &mut header);
    if header != [0u8; 8] {
        return None;
    }
    verify_and_decrypt(&frame[8..], my_x_priv, server_x_pub, server_ed)
}

// ============================== qr / invite ==============================

pub struct Peer {
    pub x_pub: [u8; 32],
    pub ed_pub: VerifyingKey,
    pub id: [u8; 8],
    pub nick: String,
}

/// Decode an invite "K0<base64url(x_pub || ed_pub || nick)>".
pub fn decode_qr(qr: &str) -> anyhow::Result<Peer> {
    let body = qr
        .trim()
        .strip_prefix(QR_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("bad invite prefix (expected {QR_PREFIX}...)"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body)?;
    if raw.len() < 64 {
        anyhow::bail!("invite too short");
    }
    let x_pub: [u8; 32] = raw[..32].try_into().unwrap();
    let ed_pub = VerifyingKey::from_bytes(&raw[32..64].try_into().unwrap())?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&x_pub[..8]);
    let nick = String::from_utf8_lossy(&raw[64..]).to_string();
    Ok(Peer { x_pub, ed_pub, id, nick })
}

/// Build a `Peer` from a CMD_INTRO_FROM body: [x_pub:32][ed_pub:32][nick...].
///
/// Used by capability "accept-incoming" mode: when the relay tells us an
/// initiator's keys, this turns that body into the same `Peer` we'd otherwise
/// have decoded from an invite. The keys come from the relay's verified view of
/// the sender's session, so they identify the real initiator.
pub fn decode_intro_from(body: &[u8]) -> anyhow::Result<Peer> {
    if body.len() < 64 {
        anyhow::bail!("intro_from body too short");
    }
    let x_pub: [u8; 32] = body[..32].try_into().unwrap();
    let ed_pub = VerifyingKey::from_bytes(&body[32..64].try_into().unwrap())?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&x_pub[..8]);
    let nick = String::from_utf8_lossy(&body[64..]).to_string();
    Ok(Peer { x_pub, ed_pub, id, nick })
}

/// Encode our invite "K0<base64url(x_pub || ed_pub || nick)>".
pub fn make_qr(me: &Identity, nick: &str) -> String {
    let mut combined = Vec::with_capacity(64 + nick.len());
    combined.extend_from_slice(&me.x_pub);
    combined.extend_from_slice(me.ed_pub.as_bytes());
    combined.extend_from_slice(nick.as_bytes());
    format!(
        "{QR_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined)
    )
}

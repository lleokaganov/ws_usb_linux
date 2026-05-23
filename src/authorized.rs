//! Capability list of authorized initiators (the "authorized-keys" table).
//!
//! Capability "accept-incoming" mode (see `tcp::run_tcp_connect_accept`) lets a
//! device-sharing gate accept a connection from anyone who knows ITS invite,
//! learning the initiator's public key from the relay's CMD_INTRO_FROM. This
//! module decides *which* initiators are allowed:
//!
//!   - File `~/.config/usbws/authorized` (alongside the identity file; honors
//!     $USBWS_IDENTITY's directory). One initiator per line:
//!         <x_pub_hex64> [optional nick...]
//!     Lines starting with '#' and blank lines are ignored.
//!   - EMPTY or MISSING file  → trust-on-first-use (TOFU): the first initiator
//!     who knows our invite is accepted and appended (knowing the invite ==
//!     being the owner). Several owners = several lines.
//!   - NON-EMPTY file → only initiators whose x_pub is listed are accepted;
//!     anyone else is rejected (and logged).

use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Resolve the authorized-keys file path: it lives in the same directory as the
/// identity file, named `authorized`. So `$USBWS_IDENTITY=/tmp/idA` →
/// `/tmp/authorized`; the default `~/.config/usbws/identity` →
/// `~/.config/usbws/authorized`.
pub fn authorized_path() -> PathBuf {
    let id = crate::idfile::identity_path();
    match id.parent() {
        Some(dir) => dir.join("authorized"),
        None => PathBuf::from("authorized"),
    }
}

/// One authorized initiator: its x_pub plus an optional human nick.
#[derive(Clone)]
pub struct Entry {
    pub x_pub: [u8; 32],
    pub nick: String,
}

/// Load the authorized table. A missing file is treated as an empty table
/// (Ok(empty vec)) so callers can apply trust-on-first-use uniformly.
pub fn load() -> anyhow::Result<Vec<Entry>> {
    let path = authorized_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "<hex64> [nick...]" — split off the first whitespace-delimited token.
        let (hexpart, nick) = match line.split_once(char::is_whitespace) {
            Some((h, rest)) => (h, rest.trim().to_string()),
            None => (line, String::new()),
        };
        match hex::decode(hexpart).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) {
            Some(x_pub) => out.push(Entry { x_pub, nick }),
            None => eprintln!("[usbws] authorized: skipping malformed line: {line:?}"),
        }
    }
    Ok(out)
}

/// True if `x_pub` is present in the table.
pub fn contains(entries: &[Entry], x_pub: &[u8; 32]) -> bool {
    entries.iter().any(|e| &e.x_pub == x_pub)
}

/// Append an initiator to the authorized file (creating it, mode 0600, if
/// needed). Idempotent: if the x_pub is already listed, this is a no-op.
pub fn add(x_pub: &[u8; 32], nick: &str) -> anyhow::Result<()> {
    let existing = load()?;
    if contains(&existing, x_pub) {
        return Ok(());
    }
    let path = authorized_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let line = if nick.is_empty() {
        format!("{}\n", hex::encode(x_pub))
    } else {
        format!("{} {}\n", hex::encode(x_pub), nick)
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        f.write_all(line.as_bytes())?;
    }
    Ok(())
}

/// Print the table to stdout (one `<hex64> <nick>` per line). Used by the
/// `usbws authorized` subcommand.
pub fn print_table() -> anyhow::Result<()> {
    let entries = load()?;
    if entries.is_empty() {
        eprintln!(
            "[usbws] authorized table empty/missing ({}) — trust-on-first-use is active",
            authorized_path().display()
        );
        return Ok(());
    }
    for e in &entries {
        if e.nick.is_empty() {
            println!("{}", hex::encode(e.x_pub));
        } else {
            println!("{} {}", hex::encode(e.x_pub), e.nick);
        }
    }
    Ok(())
}

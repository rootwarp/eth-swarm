//! Engine API JWT (execution-apis `authentication.md`).
//!
//! HS256 only: header `{"alg":"HS256","typ":"JWT"}` and an `iat` claim. `none` and every other
//! `alg` are rejected, including a token whose HMAC would verify under a different `alg`. The
//! secret is 32 bytes, hex-encoded in the systemd credential `jwtsecret`
//! (`LoadCredential=jwtsecret:<path>`), and is never logged.

use hmac::{Hmac, KeyInit, Mac};
use rustix::fd::AsFd;
use rustix::fs::{FileType, Mode, OFlags};
use sha2::Sha256;
use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// The environment variable systemd points at the unit's credentials.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";
/// Where systemd mounts each system unit's credentials: `/run/credentials/<unit>`.
pub const CREDENTIALS_ROOT: &str = "/run/credentials";
/// The credential's name: `LoadCredential=jwtsecret:<path>`.
pub const CREDENTIAL: &str = "jwtsecret";
/// A 256-bit secret (`authentication.md`).
pub const SECRET_LEN: usize = 32;
/// Hex digits of a 256-bit secret.
const HEX_LEN: usize = SECRET_LEN * 2;
/// Larger credential files are refused before they are read.
const MAX_FILE_BYTES: u64 = 128;
/// EL clients accept `iat` within this many seconds of now (`authentication.md`).
pub const IAT_SKEW_SECS: i64 = 60;
/// Modes an owned credential may have. Anything looser than `0600` is refused; `0400` is
/// systemd's mode after `fchmod`.
const OWNED_MODES: [u32; 2] = [0o600, 0o400];
/// Modes a root-owned, ACL-granted credential may have.
const ACL_MODES: [u32; 2] = [0o400, 0o440];
const ACL_XATTR: &str = "system.posix_acl_access";

const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;
type HmacSha256 = Hmac<Sha256>;

/// The JWT secret. Zeroized on drop. `Debug` and `Display` print `<redacted>`.
pub struct JwtSecret(Zeroizing<[u8; SECRET_LEN]>);

impl JwtSecret {
    /// The secret bytes. Never log them or put them in an error.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for JwtSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for JwtSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why a credential was refused. No variant carries secret bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The process runs as root.
    #[error("refusing to run as root: run as the unit's own User=")]
    Root,
    /// `$CREDENTIALS_DIRECTORY` is unset or empty.
    #[error("${CREDENTIALS_DIRECTORY} is not set: start through the systemd unit (LoadCredential={CREDENTIAL}:<path>)")]
    NoDirectory,
    /// `$CREDENTIALS_DIRECTORY` is relative.
    #[error("${CREDENTIALS_DIRECTORY} must be an absolute path")]
    NotAbsolute,
    /// The file or its directory could not be opened.
    #[error("{}: cannot open: {reason}", path.display())]
    Open { path: PathBuf, reason: String },
    /// The path is not a regular file.
    #[error("{}: not a regular file", path.display())]
    NotRegular { path: PathBuf },
    /// The mode is looser than `0600`, or not one of the modes the file's shape allows.
    #[error("{}: mode {mode:04o}, want {want}", path.display())]
    Mode {
        path: PathBuf,
        mode: u32,
        want: &'static str,
    },
    /// Neither the effective UID nor root owns the file.
    #[error("{}: owned by uid {owner}, want {euid} (or root, with an ACL for {euid})", path.display())]
    Owner {
        path: PathBuf,
        owner: u32,
        euid: u32,
    },
    /// The ACL is not the one shape allowed.
    #[error("{}: ACL: {reason}", path.display())]
    Acl { path: PathBuf, reason: String },
    /// A root-owned credential is not on this unit's read-only credentials mount.
    #[error("{}: {reason}", path.display())]
    Mount { path: PathBuf, reason: String },
    /// The file is not a 32-byte hex secret's length.
    #[error("{}: {len} bytes, want {HEX_LEN} hex characters", path.display())]
    Length { path: PathBuf, len: u64 },
    /// The bytes are not hex for 32 bytes.
    #[error("{}: not a 32-byte hex secret", path.display())]
    NotHex { path: PathBuf },
    /// Reading failed.
    #[error("{}: read: {reason}", path.display())]
    Read { path: PathBuf, reason: String },
}

/// Why a token was refused. No variant carries the secret or the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    /// Not three base64url parts, or the JSON is not an object.
    #[error("malformed JWT")]
    Malformed,
    /// `alg` is not exactly `HS256` (this includes `none` and every other algorithm).
    #[error("JWT alg is not HS256")]
    Algorithm,
    /// The HMAC does not match.
    #[error("JWT signature rejected")]
    Signature,
    /// `iat` is missing or not an integer number of seconds.
    #[error("JWT iat is missing")]
    MissingIat,
    /// `iat` is outside ±[`IAT_SKEW_SECS`] of `now`.
    #[error("JWT iat is outside the accepted window")]
    Stale,
}

/// `iat` of a token we accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claims {
    /// Seconds since the Unix epoch.
    pub iat: i64,
}

/// [`load`] with `$CREDENTIALS_DIRECTORY` and this process's effective UID.
pub fn load_from_env(unit: &str) -> Result<JwtSecret, CredentialError> {
    load(
        std::env::var_os(CREDENTIALS_DIRECTORY).as_deref(),
        rustix::process::geteuid().as_raw(),
        unit,
    )
}

/// Loads `<credentials_dir>/jwtsecret` for effective UID `euid` of unit `unit`.
///
/// Logs the path and the redacted secret, never the bytes.
pub fn load(
    credentials_dir: Option<&OsStr>,
    euid: u32,
    unit: &str,
) -> Result<JwtSecret, CredentialError> {
    let result = locate(credentials_dir, euid).and_then(|dir| {
        let path = dir.join(CREDENTIAL);
        let secret = read(dir, euid, unit)?;
        tracing::info!(
            credential = %path.display(),
            jwt_secret = %secret,
            "JWT secret loaded from the systemd credential"
        );
        Ok(secret)
    });
    if let Err(err) = &result {
        tracing::error!(error = %err, "JWT secret refused");
    }
    result
}

/// An HS256 JWT whose only claim is `iat` (seconds since the Unix epoch).
///
/// `now` before the epoch is encoded as a negative `iat`. The function does not panic.
#[must_use]
pub fn token(secret: &[u8; SECRET_LEN], now: SystemTime) -> String {
    let iat = unix_secs(now);
    let payload = format!(r#"{{"iat":{iat}}}"#);
    let signing = format!(
        "{}.{}",
        b64url_encode(HEADER.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let Some(sig) = hmac_sha256(secret, signing.as_bytes()) else {
        return String::new();
    };
    format!("{signing}.{}", b64url_encode(&sig))
}

/// Accepts `token` only when it is HS256, the HMAC matches, and `iat` is within
/// ±[`IAT_SKEW_SECS`] of `now`.
pub fn verify(secret: &[u8; SECRET_LEN], token: &str, now: SystemTime) -> Result<Claims, JwtError> {
    let (header_b64, payload_b64, sig_b64) = split_token(token).ok_or(JwtError::Malformed)?;
    let header = b64url_decode(header_b64).ok_or(JwtError::Malformed)?;
    let payload = b64url_decode(payload_b64).ok_or(JwtError::Malformed)?;
    let sig = b64url_decode(sig_b64).ok_or(JwtError::Malformed)?;
    let header_json = std::str::from_utf8(&header).map_err(|_| JwtError::Malformed)?;
    let payload_json = std::str::from_utf8(&payload).map_err(|_| JwtError::Malformed)?;
    require_hs256(header_json)?;
    let signing = format!("{header_b64}.{payload_b64}");
    if !hmac_eq(secret, signing.as_bytes(), &sig) {
        return Err(JwtError::Signature);
    }
    let iat = iat_claim(payload_json)?;
    let now_secs = unix_secs(now);
    let skew = iat
        .checked_sub(now_secs)
        .map(|delta| delta.unsigned_abs())
        .unwrap_or(u64::MAX);
    if skew > u64::try_from(IAT_SKEW_SECS).unwrap_or(u64::MAX) {
        return Err(JwtError::Stale);
    }
    Ok(Claims { iat })
}

/// The `iat` claim of `token`, without checking the signature.
#[cfg(test)]
fn iat_unverified(token: &str) -> Option<i64> {
    let (_h, payload_b64, _s) = split_token(token)?;
    let payload = b64url_decode(payload_b64)?;
    let json = std::str::from_utf8(&payload).ok()?;
    iat_claim(json).ok()
}

fn require_hs256(header_json: &str) -> Result<(), JwtError> {
    if occurrences(header_json, "\"alg\"") != 1 || occurrences(header_json, "\"typ\"") != 1 {
        return Err(JwtError::Algorithm);
    }
    let value: serde_json::Value =
        serde_json::from_str(header_json).map_err(|_| JwtError::Malformed)?;
    let alg = value.get("alg").and_then(|v| v.as_str());
    let typ = value.get("typ").and_then(|v| v.as_str());
    if alg != Some("HS256") || typ != Some("JWT") {
        return Err(JwtError::Algorithm);
    }
    Ok(())
}

fn iat_claim(payload_json: &str) -> Result<i64, JwtError> {
    let value: serde_json::Value =
        serde_json::from_str(payload_json).map_err(|_| JwtError::Malformed)?;
    value
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or(JwtError::MissingIat)
}

fn split_token(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let sig = parts.next()?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return None;
    }
    Some((header, payload, sig))
}

fn occurrences(hay: &str, needle: &str) -> usize {
    hay.match_indices(needle).count()
}

fn unix_secs(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(earlier) => i64::try_from(earlier.duration().as_secs())
            .map_or(i64::MIN, |secs| secs.saturating_neg()),
    }
}

fn hmac_sha256(secret: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    if bytes.len() != out.len() {
        return None;
    }
    out.copy_from_slice(&bytes);
    Some(out)
}

fn hmac_eq(secret: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(sig).is_ok()
}

fn b64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, rest) = data.as_chunks::<3>();
    for chunk in chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
    }
    match rest {
        [a] => {
            let n = u32::from(*a) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        [a, b] => {
            let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn val(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    if text.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut n = 0u8;
    for byte in text.bytes() {
        buf = (buf << 6) | u32::from(val(byte)?);
        n += 1;
        if n == 4 {
            out.push((buf >> 16) as u8);
            out.push((buf >> 8) as u8);
            out.push(buf as u8);
            buf = 0;
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((buf >> 4) as u8),
        3 => {
            out.push((buf >> 10) as u8);
            out.push((buf >> 2) as u8);
        }
        _ => return None,
    }
    Some(out)
}

fn locate(credentials_dir: Option<&OsStr>, euid: u32) -> Result<&Path, CredentialError> {
    if euid == 0 {
        return Err(CredentialError::Root);
    }
    let dir = match credentials_dir {
        Some(dir) if !dir.is_empty() => Path::new(dir),
        _ => return Err(CredentialError::NoDirectory),
    };
    if !dir.is_absolute() {
        return Err(CredentialError::NotAbsolute);
    }
    Ok(dir)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Grant {
    Owner,
    Acl,
}

fn read(dir: &Path, euid: u32, unit: &str) -> Result<JwtSecret, CredentialError> {
    let path = dir.join(CREDENTIAL);
    let at = || path.clone();
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir_fd =
        rustix::fs::open(dir, dir_flags, Mode::empty()).map_err(|err| CredentialError::Open {
            path: dir.to_owned(),
            reason: err.to_string(),
        })?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::openat(&dir_fd, CREDENTIAL, flags, Mode::empty()).map_err(|err| {
        CredentialError::Open {
            path: at(),
            reason: err.to_string(),
        }
    })?;
    let st = rustix::fs::fstat(&fd).map_err(|err| CredentialError::Read {
        path: at(),
        reason: err.to_string(),
    })?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(CredentialError::NotRegular { path: at() });
    }
    let acl = access_acl(&fd, &path)?;
    if grant(
        &path,
        mode_bits(st.st_mode),
        st.st_uid,
        euid,
        acl.as_deref(),
    )? == Grant::Acl
    {
        credentials_mount(&dir_fd, dir, unit)?;
    }
    let len = u64::try_from(st.st_size).unwrap_or(u64::MAX);
    if len == 0 || len > MAX_FILE_BYTES {
        return Err(CredentialError::Length { path: at(), len });
    }
    let Some(len_usize) = usize::try_from(len).ok() else {
        return Err(CredentialError::Length { path: at(), len });
    };
    let mut buf = Zeroizing::new(vec![0u8; len_usize]);
    std::fs::File::from(fd)
        .read_exact(&mut buf)
        .map_err(|err| CredentialError::Read {
            path: at(),
            reason: err.to_string(),
        })?;
    let bytes = decode_hex_secret(&buf).ok_or(CredentialError::NotHex { path: at() })?;
    Ok(JwtSecret(Zeroizing::new(bytes)))
}

/// Hex, optional `0x` prefix, optional trailing newline. Exactly 32 bytes.
fn decode_hex_secret(raw: &[u8]) -> Option<[u8; SECRET_LEN]> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    let raw = raw
        .strip_prefix(b"0x")
        .or_else(|| raw.strip_prefix(b"0X"))
        .unwrap_or(raw);
    if raw.len() != HEX_LEN {
        return None;
    }
    let mut out = [0u8; SECRET_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = hex_byte(*raw.get(i * 2)?, *raw.get(i * 2 + 1)?)?;
    }
    Some(out)
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_nibble(hi)? << 4) | hex_nibble(lo)?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn grant(
    path: &Path,
    mode: u32,
    owner: u32,
    euid: u32,
    acl: Option<&[u8]>,
) -> Result<Grant, CredentialError> {
    let refuse_acl = |reason: String| CredentialError::Acl {
        path: path.to_owned(),
        reason,
    };
    if owner == euid {
        if !OWNED_MODES.contains(&mode) {
            return Err(CredentialError::Mode {
                path: path.to_owned(),
                mode,
                want: "0600 or 0400",
            });
        }
        if acl.is_some() {
            return Err(refuse_acl(
                "an owned credential must carry no ACL: it could grant others access".into(),
            ));
        }
        return Ok(Grant::Owner);
    }
    if owner != 0 {
        return Err(CredentialError::Owner {
            path: path.to_owned(),
            owner,
            euid,
        });
    }
    if !ACL_MODES.contains(&mode) {
        return Err(CredentialError::Mode {
            path: path.to_owned(),
            mode,
            want: "0400 or 0440 for a root-owned credential",
        });
    }
    let acl = acl.ok_or_else(|| refuse_acl(format!("root's file and no ACL grants uid {euid}")))?;
    check_acl(acl, euid).map_err(refuse_acl)?;
    Ok(Grant::Acl)
}

#[cfg(target_os = "linux")]
fn access_acl(fd: &impl AsFd, path: &Path) -> Result<Option<Vec<u8>>, CredentialError> {
    use rustix::io::Errno;
    let mut buf = [0u8; 4 + 8 * 16];
    match rustix::fs::fgetxattr(fd, ACL_XATTR, &mut buf) {
        Ok(len) => Ok(Some(buf[..len].to_vec())),
        Err(Errno::NODATA | Errno::OPNOTSUPP | Errno::NOSYS) => Ok(None),
        Err(Errno::RANGE) => Err(CredentialError::Acl {
            path: path.to_owned(),
            reason: "more than 16 entries".into(),
        }),
        Err(err) => Err(CredentialError::Read {
            path: path.to_owned(),
            reason: format!("{ACL_XATTR}: {err}"),
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn access_acl(_fd: &impl AsFd, _path: &Path) -> Result<Option<Vec<u8>>, CredentialError> {
    Ok(None)
}

fn credentials_mount(dir_fd: &impl AsFd, dir: &Path, unit: &str) -> Result<(), CredentialError> {
    let refuse = |reason: String| CredentialError::Mount {
        path: dir.to_owned(),
        reason,
    };
    if unit.is_empty() || unit == "." || unit == ".." || unit.contains('/') {
        return Err(refuse(format!("{unit:?} is not a unit name")));
    }
    let want = Path::new(CREDENTIALS_ROOT).join(unit);
    if dir.as_os_str() != want.as_os_str() {
        return Err(refuse(format!(
            "a root-owned credential is accepted only from {}, this unit's systemd credentials",
            want.display()
        )));
    }
    credentials_fs(dir_fd).map_err(refuse)
}

#[cfg(target_os = "linux")]
const CREDENTIALS_FS_MAGIC: [i64; 2] = [0x0102_1994, 0x8584_58f6];

#[cfg(target_os = "linux")]
fn credentials_fs(dir_fd: &impl AsFd) -> Result<(), String> {
    let fs = rustix::fs::fstatfs(dir_fd).map_err(|err| format!("fstatfs: {err}"))?;
    #[allow(clippy::unnecessary_cast, clippy::cast_possible_wrap)]
    let magic = i64::from(fs.f_type as u32);
    if !CREDENTIALS_FS_MAGIC.contains(&magic) {
        return Err(format!(
            "filesystem type {magic:#x}, want tmpfs or ramfs (systemd's credentials mount)"
        ));
    }
    let vfs = rustix::fs::fstatvfs(dir_fd).map_err(|err| format!("fstatvfs: {err}"))?;
    if !vfs.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY) {
        return Err("mounted read-write: systemd's credentials mount is read-only".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn credentials_fs(_dir_fd: &impl AsFd) -> Result<(), String> {
    Err("a root-owned, ACL-granted credential is accepted only on Linux".into())
}

const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const ACL_READ: u16 = 0x04;
const ACL_XATTR_VERSION: u32 = 2;

struct AclEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

fn decode_acl(bytes: &[u8]) -> Result<Vec<AclEntry>, String> {
    let Some((version, entries)) = bytes.split_first_chunk::<4>() else {
        return Err(format!("{} bytes: no header", bytes.len()));
    };
    let version = u32::from_le_bytes(*version);
    if version != ACL_XATTR_VERSION {
        return Err(format!("version {version}, want {ACL_XATTR_VERSION}"));
    }
    if !entries.len().is_multiple_of(8) {
        return Err(format!(
            "{} bytes of entries, not a multiple of 8",
            entries.len()
        ));
    }
    let (entries, _) = entries.as_chunks::<8>();
    Ok(entries
        .iter()
        .map(|entry| AclEntry {
            tag: u16::from_le_bytes([entry[0], entry[1]]),
            perm: u16::from_le_bytes([entry[2], entry[3]]),
            id: u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
        })
        .collect())
}

/// Exactly systemd's `write_credential()` ACL for `euid`.
fn check_acl(bytes: &[u8], euid: u32) -> Result<(), String> {
    let entries = decode_acl(bytes)?;
    let want = [
        (ACL_USER_OBJ, ACL_READ, "user::r--"),
        (ACL_USER, ACL_READ, "user:<euid>:r--"),
        (ACL_GROUP_OBJ, 0, "group::---"),
        (ACL_MASK, ACL_READ, "mask::r--"),
        (ACL_OTHER, 0, "other::---"),
    ];
    let shape = "want exactly user::r--, user:<euid>:r--, group::---, mask::r--, other::---";
    if entries.len() != want.len() {
        return Err(format!("{} entries; {shape}", entries.len()));
    }
    for (tag, perm, name) in want {
        let mut matching = entries.iter().filter(|entry| entry.tag == tag);
        let (Some(entry), None) = (matching.next(), matching.next()) else {
            return Err(format!("not exactly one {name} entry; {shape}"));
        };
        if tag == ACL_USER && entry.id != euid {
            return Err(format!("the named user is uid {}, not {euid}", entry.id));
        }
        if entry.perm != perm {
            return Err(format!("{name} has permissions {:#o}; {shape}", entry.perm));
        }
    }
    Ok(())
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)]
fn mode_bits(raw: rustix::fs::RawMode) -> u32 {
    (raw as u32) & 0o7777
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const UNIT: &str = "ethswarm-engine.service";
    /// Known-answer secret: 32 bytes of `0x11`.
    const SECRET: [u8; 32] = [0x11; 32];
    const ISSUED_AT: u64 = 1_700_000_000;
    /// `token(&SECRET, UNIX_EPOCH + 1_700_000_000s)`, computed independently (Python hmac/sha256).
    const KNOWN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDB9.Hb09lNHg9IiC1UttHzXRW1voUqjM97m4oEuKWkSux5g";

    fn issued_at() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(ISSUED_AT)
    }

    fn euid() -> u32 {
        match rustix::process::geteuid().as_raw() {
            0 => 4242,
            euid => euid,
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    fn credentials(mode: u32, text: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIAL);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        if rustix::process::geteuid().is_root() {
            let owner = Some(rustix::process::Uid::from_raw(euid()));
            rustix::fs::chown(&path, owner, None).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn load_in(dir: &tempfile::TempDir) -> Result<JwtSecret, CredentialError> {
        load(Some(dir.path().as_os_str()), euid(), UNIT)
    }

    #[test]
    fn known_answer_hs256() {
        let token = token(&SECRET, issued_at());
        assert_eq!(token, KNOWN);
        let header = b64url_decode(token.split('.').next().unwrap()).unwrap();
        assert_eq!(header, HEADER.as_bytes());
        assert!(!header.windows(4).any(|w| w == b"none"));
        let claims = verify(&SECRET, &token, issued_at()).unwrap();
        assert_eq!(claims.iat, i64::try_from(ISSUED_AT).unwrap());
    }

    #[test]
    fn iat_within_one_second_of_now() {
        let now = SystemTime::now();
        let token = token(&SECRET, now);
        let iat = iat_unverified(&token).unwrap();
        let now_secs = unix_secs(now);
        assert!(iat.abs_diff(now_secs) <= 1, "iat {iat} now {now_secs}");
        assert!(verify(&SECRET, &token, now).is_ok());
    }

    #[test]
    fn iat_changes_when_now_changes() {
        let first = token(&SECRET, issued_at());
        let second = token(&SECRET, issued_at() + Duration::from_secs(5));
        assert_ne!(
            iat_unverified(&first).unwrap(),
            iat_unverified(&second).unwrap()
        );
    }

    #[test]
    fn iat_window_is_sixty_seconds() {
        let now = issued_at();
        let on_edge = token(&SECRET, now + Duration::from_secs(60));
        assert!(verify(&SECRET, &on_edge, now).is_ok());
        let early = token(&SECRET, now - Duration::from_secs(60));
        assert!(verify(&SECRET, &early, now).is_ok());
        let late = token(&SECRET, now + Duration::from_secs(61));
        assert_eq!(verify(&SECRET, &late, now).unwrap_err(), JwtError::Stale);
        let too_early = token(&SECRET, now - Duration::from_secs(61));
        assert_eq!(
            verify(&SECRET, &too_early, now).unwrap_err(),
            JwtError::Stale
        );
    }

    #[test]
    fn none_is_never_produced() {
        let token = token(&SECRET, issued_at());
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(token.split('.').next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["typ"], "JWT");
        assert!(!token.to_ascii_lowercase().contains("none"));
    }

    #[test]
    fn none_and_other_algs_are_rejected() {
        let payload = b64url_encode(br#"{"iat":1700000000}"#);
        let cases = [
            r#"{"alg":"none","typ":"JWT"}"#,
            r#"{"alg":"None","typ":"JWT"}"#,
            r#"{"alg":"NONE","typ":"JWT"}"#,
            r#"{"alg":"HS384","typ":"JWT"}"#,
            r#"{"alg":"RS256","typ":"JWT"}"#,
            r#"{"alg":"HS256","alg":"none","typ":"JWT"}"#,
            r#"{"alg":"none","alg":"HS256","typ":"JWT"}"#,
        ];
        for header in cases {
            let signing = format!("{}.{}", b64url_encode(header.as_bytes()), payload);
            let sig = hmac_sha256(&SECRET, signing.as_bytes()).unwrap();
            let signed = format!("{signing}.{}", b64url_encode(&sig));
            let unsigned = format!("{signing}.");
            for token in [signed, unsigned] {
                let err = verify(&SECRET, &token, issued_at()).unwrap_err();
                assert_eq!(err, JwtError::Algorithm, "{header} -> {token}");
                assert!(!err.to_string().contains("1111"), "{err}");
            }
        }
    }

    #[test]
    fn a_bad_signature_is_rejected() {
        let mut token = token(&SECRET, issued_at());
        token.pop();
        token.push('A');
        assert_eq!(
            verify(&SECRET, &token, issued_at()).unwrap_err(),
            JwtError::Signature
        );
        let other = [0x22; 32];
        assert_eq!(
            verify(&other, KNOWN, issued_at()).unwrap_err(),
            JwtError::Signature
        );
    }

    #[test]
    fn loads_hex_from_an_owner_only_file() {
        let hex = hex_encode(&SECRET);
        for mode in OWNED_MODES {
            for text in [hex.clone(), format!("{hex}\n"), format!("0x{hex}\n")] {
                let dir = credentials(mode, &text);
                let secret = load_in(&dir).unwrap();
                assert_eq!(secret.expose_secret(), &SECRET, "{mode:o} {text:?}");
            }
        }
    }

    #[test]
    fn short_or_malformed_secret_is_refused() {
        let short = "00112233445566778899aabbccddeeff";
        let dir = credentials(0o600, short);
        assert!(
            matches!(load_in(&dir).unwrap_err(), CredentialError::NotHex { .. }),
            "short hex"
        );
        let dir = credentials(
            0o600,
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
        let err = load_in(&dir).unwrap_err();
        assert!(matches!(err, CredentialError::NotHex { .. }), "{err:?}");
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("zzzzzzzz"), "{shown}");
        for wrong_length in [
            &hex_encode(&SECRET)[..62],
            &format!("{}00", hex_encode(&SECRET)),
        ] {
            let dir = credentials(0o600, wrong_length);
            let err = load_in(&dir).unwrap_err();
            assert!(
                matches!(
                    err,
                    CredentialError::NotHex { .. } | CredentialError::Length { .. }
                ),
                "{} chars: {err:?}",
                wrong_length.len()
            );
            assert!(!format!("{err} {err:?}").contains("1111"), "{err:?}");
        }
        let dir = credentials(0o600, "");
        assert!(matches!(
            load_in(&dir).unwrap_err(),
            CredentialError::Length { .. }
        ));
    }

    #[test]
    fn loose_mode_is_refused() {
        let hex = hex_encode(&SECRET);
        for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o700, 0o4600] {
            let dir = credentials(mode, &hex);
            let err = load_in(&dir).unwrap_err();
            assert!(
                matches!(err, CredentialError::Mode { mode: got, .. } if got == mode),
                "{mode:o}: {err:?}"
            );
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains(&hex), "{shown}");
        }
    }

    #[test]
    fn secret_absent_from_debug_and_errors() {
        let dir = credentials(0o600, &hex_encode(&SECRET));
        let secret = load_in(&dir).unwrap();
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("11"));
        let loose = credentials(0o644, &hex_encode(&SECRET));
        let err = load_in(&loose).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&hex_encode(&SECRET)), "{shown}");
        assert!(!shown.contains("11111111"), "{shown}");
    }

    #[test]
    fn refuses_root_a_relative_dir_a_symlink_and_another_owner() {
        let dir = credentials(0o600, &hex_encode(&SECRET));
        assert_eq!(
            load(Some(dir.path().as_os_str()), 0, UNIT).unwrap_err(),
            CredentialError::Root
        );
        assert_eq!(
            load(None, euid(), UNIT).unwrap_err(),
            CredentialError::NoDirectory
        );
        assert_eq!(
            load(Some(OsStr::new("creds")), euid(), UNIT).unwrap_err(),
            CredentialError::NotAbsolute
        );
        let linked = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join(CREDENTIAL), linked.path().join(CREDENTIAL))
            .unwrap();
        assert!(matches!(
            load_in(&linked).unwrap_err(),
            CredentialError::Open { .. }
        ));
        let err = load(Some(dir.path().as_os_str()), euid() + 1, UNIT).unwrap_err();
        assert!(matches!(err, CredentialError::Owner { .. }), "{err:?}");
    }
}

use clap::Subcommand;
use openwarp_crypto as oc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_ENVELOPE: usize = 24 * 1024 * 1024;
const PAYLOAD_AAD: &[u8] = b"openwarp-file:payload:v1";
const INVALID: &str = "invalid encrypted file or identity, or authentication failed";

#[derive(Subcommand)]
pub(crate) enum FileCmd {
    /// Generate an offline X25519 identity in a new private file
    Keygen { #[arg(long)] out: String },
    /// Encrypt bytes for one or more recipients without contacting the server
    Encrypt { input: String, #[arg(long, required = true)] recipient: Vec<String>, #[arg(long)] out: String },
    Decrypt { input: String, #[arg(long)] identity: String, #[arg(long)] out: String },
    /// Replace recipients without changing the payload (old copies remain decryptable)
    Rekey { input: String, #[arg(long)] identity: String, #[arg(long, required = true)] recipient: Vec<String>, #[arg(long)] out: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity { public_key: String, private_key: String }
impl Drop for Identity { fn drop(&mut self) { use zeroize::Zeroize; self.private_key.zeroize(); } }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipient { public_key: String, wrapped_key: String }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { version: u32, payload: String, recipients: Vec<Recipient>, authentication: String }

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = std::fs::File::open(path).map_err(|_| "could not read input file")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| "could not read input file")?;
    if bytes.len() > limit { return Err("input exceeds size limit".into()); }
    Ok(bytes)
}

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(path).map_err(|_| "output must be a new writable file")?;
    // Unlink an incomplete newly-created file; never open an existing path for writing.
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = std::fs::remove_file(path); return Err("could not write output file".into());
    }
    Ok(())
}

pub(crate) fn public_key(raw: &str) -> Result<String, String> {
    let bytes: [u8;32] = oc::unb64(raw).map_err(|_| INVALID)?.try_into().map_err(|_| INVALID)?;
    // X25519 ignores the high bit; require a canonical field encoding to prevent aliases.
    let mut prime = [255u8;32]; prime[0] = 237; prime[31] = 127;
    if bytes.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less { return Err(INVALID.into()); }
    let probe = StaticSecret::from([0x42;32]);
    if probe.diffie_hellman(&PublicKey::from(bytes)).as_bytes() == &[0u8;32] { return Err(INVALID.into()); }
    Ok(oc::b64(&bytes))
}

pub(crate) fn load_identity(path: &Path) -> Result<oc::Keypair, String> {
    let bytes = read_bounded(path, 4096)?;
    let identity: Identity = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    let secret = Zeroizing::new(oc::unb64(&identity.private_key).map_err(|_| INVALID)?);
    if secret.len() != 32 { return Err(INVALID.into()); }
    let kp = oc::Keypair::from_secret_b64(&identity.private_key).map_err(|_| INVALID)?;
    if public_key(&identity.public_key)? != kp.public { return Err(INVALID.into()); }
    Ok(kp)
}

fn recipients(keys: &[String], dek: &[u8;32]) -> Result<Vec<Recipient>, String> {
    if keys.is_empty() || keys.len() > 32 { return Err("provide between 1 and 32 unique recipients".into()); }
    let mut seen = HashSet::new(); let mut result = Vec::new();
    for key in keys {
        let public_key = public_key(key)?;
        if !seen.insert(public_key.clone()) { return Err("duplicate recipient".into()); }
        let wrapped_key = oc::encrypt_to(&public_key, dek).map_err(|_| INVALID)?;
        result.push(Recipient { public_key, wrapped_key });
    }
    Ok(result)
}

fn metadata(envelope: &Envelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&("openwarp-file:metadata:v1", envelope.version, &envelope.payload, &envelope.recipients)).map_err(|_| INVALID.into())
}
fn authenticate(envelope: &mut Envelope, dek: &[u8;32]) -> Result<(), String> {
    envelope.authentication = oc::encrypt_symmetric_aad(dek, &metadata(envelope)?, b""); Ok(())
}
type OpenedFile = (Envelope, Zeroizing<[u8;32]>, Zeroizing<Vec<u8>>);
fn open(input: &Path, identity: &Path) -> Result<OpenedFile, String> {
    let bytes = read_bounded(input, MAX_ENVELOPE)?;
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    if envelope.version != 1 || envelope.recipients.is_empty() || envelope.recipients.len() > 32 { return Err(INVALID.into()); }
    let mut seen = HashSet::new();
    for r in &envelope.recipients {
        if public_key(&r.public_key)? != r.public_key || !seen.insert(&r.public_key) { return Err(INVALID.into()); }
        let wrapped = oc::unb64(&r.wrapped_key).map_err(|_| INVALID)?;
        if wrapped.len() != 104 { return Err(INVALID.into()); }
        public_key(&oc::b64(&wrapped[..32]))?;
    }
    let kp = load_identity(identity)?;
    let recipient = envelope.recipients.iter().find(|r| r.public_key == kp.public).ok_or(INVALID)?;
    let raw = Zeroizing::new(kp.decrypt(&recipient.wrapped_key).map_err(|_| INVALID)?);
    if raw.len() != 32 { return Err(INVALID.into()); }
    let mut dek = Zeroizing::new([0u8;32]); dek.copy_from_slice(&raw);
    let tag_plain = Zeroizing::new(oc::decrypt_symmetric_aad(&dek, &metadata(&envelope)?, &envelope.authentication).map_err(|_| INVALID)?);
    if !tag_plain.is_empty() { return Err(INVALID.into()); }
    let plaintext = Zeroizing::new(oc::decrypt_symmetric_aad(&dek, PAYLOAD_AAD, &envelope.payload).map_err(|_| INVALID)?);
    if plaintext.len() > MAX_INPUT { return Err(INVALID.into()); }
    Ok((envelope, dek, plaintext))
}

pub(crate) fn execute(command: &FileCmd) -> Result<(), String> {
    match command {
        FileCmd::Keygen { out } => {
            let kp = oc::Keypair::generate();
            let identity = Identity { public_key: kp.public.clone(), private_key: kp.secret_b64() };
            let bytes = Zeroizing::new(serde_json::to_vec_pretty(&identity).map_err(|_| INVALID)?);
            write_new(Path::new(out), &bytes)
        }
        FileCmd::Encrypt { input, recipient, out } => {
            let dek = Zeroizing::new(oc::random_key());
            let recipients = recipients(recipient, &dek)?;
            let plaintext = read_bounded(Path::new(input), MAX_INPUT)?;
            let payload = oc::encrypt_symmetric_aad(&dek, PAYLOAD_AAD, &plaintext);
            let mut envelope = Envelope { version: 1, payload, recipients, authentication: String::new() };
            authenticate(&mut envelope, &dek)?;
            write_new(Path::new(out), &serde_json::to_vec_pretty(&envelope).map_err(|_| INVALID)?)
        }
        FileCmd::Decrypt { input, identity, out } => {
            let (_, _, plaintext) = open(Path::new(input), Path::new(identity))?;
            write_new(Path::new(out), &plaintext)
        }
        FileCmd::Rekey { input, identity, recipient, out } => {
            let (mut envelope, dek, _plaintext) = open(Path::new(input), Path::new(identity))?;
            envelope.recipients = recipients(recipient, &dek)?; authenticate(&mut envelope, &dek)?;
            write_new(Path::new(out), &serde_json::to_vec_pretty(&envelope).map_err(|_| INVALID)?)
        }
    }
}

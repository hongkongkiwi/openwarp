# Client-derived authentication protocol

Status: implemented for new accounts, password reset, explicit upgrade and the
OAuth consent page. Version 1 password accounts keep working until they reset or
upgrade.

## Why

Version 1 registration and login send the password to the server, and the server
uses it to wrap the user's X25519 private key. That means a malicious operator
can capture the password and unwrap every end-to-end environment. Encrypting the
database and the transport does not change that.

This protocol removes the password and the wrapping key from the server. It is
not a PAKE: the server still learns an authentication key, so it can impersonate
the account. It cannot derive the wrapping key, so it cannot decrypt end-to-end
data. OPAQUE would also prevent impersonation and is the next step if that
matters.

## Key derivation

The client derives 64 bytes with PBKDF2-HMAC-SHA256:

```text
salt       = 16 random bytes, per account
iterations = 600000
output     = PBKDF2(password, salt, iterations, SHA-256, 64 bytes)
auth_key   = output[0..32]
wrap_key   = output[32..64]
```

The split is domain separation by output block. The CLI uses the same parameters
through the `pbkdf2` crate; the browser uses WebCrypto. The parameters travel
with the account so they can be raised later without breaking old accounts.

The private key is wrapped with AES-256-GCM under `wrap_key`:

```text
nonce      = 12 random bytes
ciphertext = AES-256-GCM(wrap_key, nonce, private_key, aad = empty)
wrapped    = "owv2:" + base64(nonce || ciphertext)
```

The browser uses `crypto.subtle`; the CLI uses the `aes-gcm` crate. The X25519
keypair is generated on the client, so the server never sees the private key at
registration.

## Registration

1. `GET /api/auth/kdf?email=...` returns
   `{version, salt, iterations, algo}`. A new address gets a fresh random salt;
   a version 2 account gets its stored salt; a version 1 account returns
   `{version:1}`.
2. The client derives `auth_key` and `wrap_key`, generates an X25519 keypair,
   and wraps the private key.
3. `POST /api/auth/register-v2`:

```json
{
  "email": "user@example.com",
  "salt": "base64-16-bytes",
  "iterations": 600000,
  "algo": "pbkdf2-sha256",
  "auth_key": "base64-32-bytes",
  "public_key": "base64-32-bytes",
  "wrapped_privkey": "owv2:..."
}
```

The server stores `auth_key` encrypted under the instance root with AAD
`auth-key|<user-id>`, stores the KDF parameters and the wrapped private key, sets
`auth_version=2`, and creates the account and owner organisation exactly like
version 1. It never receives the password, the wrapping key or the private key.
Email verification and signup policy apply unchanged.

## Login

1. `GET /api/auth/kdf?email=...` returns the account's KDF parameters, or
   `version:1` for a legacy account.
2. `POST /api/auth/challenge {email}` returns
   `{challenge_id, challenge, expires_at}`. Challenges last two minutes, are
   single-use, and replace any previous challenge for the account.
3. The client derives `auth_key` and computes
   `proof = HMAC-SHA256(auth_key, challenge + "|" + challenge_id)` as lowercase
   hex.
4. `POST /api/auth/login-v2 {email, challenge_id, proof}` verifies the proof with
   a constant-time comparison, consumes the challenge, and returns the same
   shapes as version 1: either `{mfa_required, mfa_token, methods,
   email_available}` or a session with `{token, user_id, public_key,
   wrapped_privkey}`.

Wrong proofs count against the existing per-address and per-account login
budget. A replayed proof fails because the challenge is already consumed. A
version 2 account cannot use the password endpoint: its stored password hash is
random and unused.

## Password reset

A reset link proves the mailbox. The client chooses a new salt, derives new
keys, and either wraps the private key from the recovery kit or generates a new
keypair (which loses access to existing end-to-end environments).

```json
POST /api/auth/reset-v2
{
  "token": "reset-link-token",
  "salt": "...", "iterations": 600000, "algo": "pbkdf2-sha256",
  "auth_key": "...", "public_key": "...", "wrapped_privkey": "owv2:..."
}
```

The server marks the token used, revokes sessions and OAuth tokens, stores the
new fields, sets `auth_version=2`, and issues a session or MFA challenge. This
also upgrades a version 1 account.

## Upgrade

`POST /api/me/upgrade-auth` accepts the same KDF fields and wrapped key for an
authenticated version 1 account. The client must hold the private key, so it
needs the recovery kit (browser Settings) or the current password (CLI, which
can unwrap the version 1 blob locally). The server never sees the password or
the wrapping key. Version 1 accounts that do not upgrade keep the old behaviour.

## MFA and OAuth consent

After a successful v2 proof, login continues through the existing MFA challenge:
TOTP, passkey or emailed code. The OAuth consent page gets a small script that
derives the keys from the email and password in the form, requests a challenge,
and posts the proof with the authorization parameters. Version 1 accounts fall
back to the existing password form. The consent page never sends the password
for a version 2 account.

## What this does not fix

- The server stores `auth_key` and can authenticate as the user. It cannot
  derive `wrap_key`, so it cannot decrypt end-to-end data.
- The browser client is served by the server. A malicious operator can serve a
  modified client and capture the password or keys. Native or signed clients
  remain the only way to close that.
- Metadata and managed environments are unchanged; this protocol protects
  end-to-end private keys and removes the password from the server.

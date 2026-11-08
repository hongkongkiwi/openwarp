# Security Policy

risaml is Rhein Industries' maintained fork of
[saml-rs](https://github.com/salasebas/opensaml-rs). Security problems in
risaml are handled by Rhein Industries. Please do not send risaml reports to
the saml-rs author.

This project is experimental. It implements SAML 2.0 **Service Provider** and
**Identity Provider** flows, and XML cryptography (signature verification,
encryption, C14N) is delegated to `ribergshamra` behind the default
`crypto-ribergshamra` feature. Do not use `risaml` for production
authentication until it is explicitly documented as stable.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

<https://github.com/Rhein-Industries/risaml/security/advisories/new>

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Please include the affected version or commit, the enabled
features (document provider, `crypto-legacy-algorithms`,
`crypto-post-quantum`, `crypto-pkcs11`), the SAML role, binding and flow
involved, and a description of the impact with, if possible, a minimal
reproduction such as a SAML message or metadata document.

We acknowledge reports as soon as we can and agree on a disclosure timeline
with the reporter. Fixes are released as a patch release and announced
through a GitHub security advisory. If the problem also affects upstream
saml-rs, we notify its author privately before any public disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 0.6.x (latest) | Yes |
| < 0.6 | No (saml-rs releases; see upstream) |

## Scope

Security-sensitive behavior includes SAML signature verification,
signed-reference selection, replay/audience checks, destination/recipient
validation, assertion decryption, XML parsing limits, and template escaping.

Security fixes should include regression tests and should fail closed with
explicit `SamlError` variants where practical.

XML-DSig, XML-Enc and C14N are provided by
[ribergshamra](https://github.com/Rhein-Industries/ribergshamra) and the
cryptographic primitives by
[riptering](https://github.com/Rhein-Industries/riptering); see their security
policies for issues in those layers.

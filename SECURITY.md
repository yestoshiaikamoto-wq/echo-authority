# Security policy

## Current status

Echo Authority Protocol 0.2 is a reference implementation. Do not use it as the sole control
for real funds, irreversible actions, or highly sensitive data until an independent audit and
the deployment-specific controls below have been completed.

## Reporting a vulnerability

Report security issues privately to `echo@moneymusk.space`. Include the affected version,
reproduction steps, impact, and any suggested mitigation. Please do not include live secrets,
private user data, or destructive proof against production systems.

The project should acknowledge a report within three business days, provide an initial severity
assessment within seven days, and coordinate disclosure after a fix is available.

## Deployment requirements

- Build issuer and gateway trust registries from operator-controlled configuration.
- Execute `authorize_and_record` and persistent state updates in one serializable transaction.
- Protect signing keys with an HSM, KMS, secure enclave, or equivalent isolated signer.
- Reject requests larger than the gateway's documented limit before JSON parsing.
- Rate-limit by issuer, subject, source, and capability.
- Store revocation state durably and define a fail-closed freshness policy.
- Log opaque decision metadata without secrets, memory content, or private keys.
- Pin released dependencies and run dependency, fuzz, and static analysis in release CI.
- Test backup restoration, key rotation, emergency revocation, and receipt-chain recovery.

## Audit scope required before production

The external review should cover canonical encodings, key binding, authorization and delegation,
state races, replay and revocation, receipt verification, WASM memory safety, parser limits,
cryptographic key lifecycle, and the production gateway that performs the protected action.

# Echo Authority Protocol — hardened Rust reference

Echo Authority Protocol is a human-rooted authorization layer for autonomous systems.
An AI may propose an action; execution requires a bounded grant issued by a trusted human key.

Version 0.2 is a security-breaking upgrade from Draft 0.1. It closes the weaknesses found in
the first adversarial review:

- issuer names resolve to verifier-controlled public keys;
- every grant binds the subject's public key;
- every invocation carries the content-derived id of its signed grant;
- signed encodings use length-prefixed fields;
- money uses non-negative integer minor units;
- the full delegation surface can only narrow;
- authorization consumption has one explicit state transition;
- receipts can be signed and verified against a registered gateway key;
- CLI key generation uses operating-system cryptographic randomness;
- protocol capability names and the implementation use the same vocabulary.

## Verify it

```sh
git clone https://github.com/yestoshiaikamoto-wq/echo-authority.git
cd echo-authority/echo-authority-rust
cargo test --all-targets
```

CI also runs formatting, Clippy with warnings denied, a native test build, the WebAssembly build,
and JSON validation of the browser vectors.

## Repository map

| Path | Purpose |
|---|---|
| `echo-authority-rust/src/lib.rs` | Deterministic verifier, state transition, attenuation, and signed receipts |
| `echo-authority-rust/tests/conformance.rs` | Expected behavior plus adversarial regression tests |
| `echo-authority-rust/src/bin/echo-authority-cli.rs` | Secure key generation, minting, invocation, verification, and receipt tools |
| `echo-authority-rust/src/bin/dump-vectors.rs` | Deterministically signed browser fixtures |
| `echo-authority-wasm` | The same verifier compiled for the browser |

## Integration rules

`border_check` is a pure decision function. A real gateway must use `authorize_and_record` inside
one database transaction or process-wide lock. This prevents two concurrent requests from using
the same nonce, use budget, or remaining spend.

The verifier returns canonical receipt claims after an allow decision. The enforcing gateway
must call `sign_receipt` with its registered key before presenting the receipt as evidence.
Consumers verify it with `verify_signed_receipt` and a verifier-controlled gateway registry.

Issuer and gateway registries are trust inputs. Never accept either registry from the same
untrusted request being evaluated.

## Security status

This remains a reference implementation until an independent security review and production
deployment assessment are complete. See [SECURITY.md](SECURITY.md) for reporting and deployment
guidance.

The code is dual licensed under MIT or Apache-2.0. Fork it, test it, and challenge every boundary.

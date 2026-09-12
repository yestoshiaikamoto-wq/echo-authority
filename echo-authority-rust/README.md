# echo-authority-core 0.2

Hardened reference implementation of the Echo Authority Protocol.

The verifier accepts a privileged invocation only when:

1. the issuer key matches a verifier-controlled trust registry;
2. the Authority Object has a valid issuer signature;
3. the invocation key matches the subject key bound into that grant;
4. the invocation signature is valid;
5. its authority id equals the hash of the signed grant;
6. capability, resource, amount, currency, time, use, audience, nonce, revocation,
   offline, and human-confirmation constraints all pass.

Money is represented in integer minor units. Signed objects use deterministic,
length-prefixed encodings. The protocol's forbidden capability names are enforced exactly.

```sh
cargo test --all-targets
cargo run --bin echo-authority-cli -- keygen
```

`keygen` uses operating-system cryptographic randomness. Its `seed_hex` output is a private
key and must be written directly to protected secret storage rather than logs or shell history.

Use `authorize_and_record` inside one database transaction or lock in a shared deployment.
After an allow decision, sign the returned receipt claims with `sign_receipt`; consumers verify
the signature and registered gateway key with `verify_signed_receipt`.

Version 0.2 intentionally changes the Draft 0.1 wire format and is not backward compatible.
The project remains a reference implementation pending independent security review.

Licensed under MIT or Apache-2.0.

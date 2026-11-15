# Echo Authority Protocol — Rust reference implementation

**A human-rooted authority layer for autonomous systems.**

> AI can propose anything. It can only execute what a human has cryptographically authorized.

This repository preserves the standalone Echo Authority **Draft 0.1** Rust reference
and its native/WASM conformance vectors.

**Compatibility status:** Money Musk at commit
`59886a74e35cb0ecb7a555a8836a623f9e846840` has a TypeScript authority profile 0.2,
an evolved embedded Rust verifier, and HAP-1/1 (implementation release 0.4.0).
Those signed formats are distinct from this standalone draft. Matching the vectors
here does not establish compatibility with current Money Musk or production safety.
Do not reinterpret old signatures or use a legacy-verifier fallback on rejection.

The CLI entropy fix leaves Draft 0.1 signing bytes, schemas, verdicts, and vectors
unchanged. It does not implement the superseded protocol-v0.2 proposal from PR #1.

## Verify it yourself, in about thirty seconds

```sh
git clone https://github.com/yestoshiaikamoto-wq/echo-authority.git
cd echo-authority/echo-authority-rust
cargo test
```

Expected:

```
test result: ok. 22 passed; 0 failed
```

Eighteen of those are hostile Border Control vectors — each bends exactly one thing about a
well-formed request and asserts the precise reason code the verifier must return
(`VALUE_LIMIT_EXCEEDED`, `NONCE_REPLAY`, `BAD_INVOCATION_SIGNATURE`, `REVOCATION_STALE`, and so
on). The remaining conformance tests cover attenuation and resource containment.
Additional CLI tests cover key generation and deterministic signing compatibility.

You do not have to trust this README. Run the suite and break it.

## What's in here

| Crate | What it is |
|-------|-----------|
| [`echo-authority-core`](./echo-authority-rust) | The verifier: types, canonical serialization, the deterministic `border_check`, attenuation-only delegation, plus three binaries — `echo-border-control` (enforcement proxy), `echo-authority-cli` (keygen / mint / invoke / verify / attenuate), and `dump-vectors` (signed fixtures). |
| [`echo-authority-wasm`](./echo-authority-wasm) | The same core compiled to `wasm32-unknown-unknown` over a raw pointer ABI, so the identical verifier runs in a browser. Not a second implementation — a second runtime. |

## The three invariants

Everything above rests on these. They are not guidelines; they are the spine.

1. **No Authority Object → no privileged action.**
2. **No valid Invocation → no execution.**
3. **No receipt → no *verifiable* claim of completion.**

The third is deliberately narrow. A bank could transfer funds and crash before signing a
receipt — the consequence still happened. We govern evidence, not reality.

## The verifier is deliberately boring

No model. No heuristics. No network. Twelve gates in a fixed order, each returning the exact
reason it failed: signatures, subject, capability, resource, value caps, time window, uses
budget, audience, nonce freshness, revocation freshness, the never-grantable set, and human
confirmation. Only if all twelve pass does it allow the action and mint an opaque receipt head.

Proof, never data. The receipt commits to *that something happened* without carrying *what*.

## A standard, not a moat

The protocol belongs to everyone. Money Musk implements it and demonstrates it; anyone may
fork it, audit it, re-implement it, or ship a competing verifier. There is no registry to join,
no key to request, no attribution required.

Dual-licensed under [MIT](./echo-authority-rust/LICENSE-MIT) or
[Apache-2.0](./echo-authority-rust/LICENSE-APACHE), at your option — the Rust convention, chosen
so the licensing is never the reason someone can't adopt it.

## What is not yet proven

An implementation that only advertised its wins would be marketing. The honest gaps, kept
current at [moneymusk.space/verify](https://moneymusk.space/verify):

- **No third-party security audit.** The vectors are ours. Adversarial review by people with no
  stake in the result is the thing that would make this trustworthy, and it hasn't happened.
- **No mapping onto W3C DIDs, Verifiable Credentials, or KERI.** Today, adopting this means
  adopting our vocabulary rather than slotting into standards you already run. This is the most
  important gap we know of.
- **Six known gaps in Draft 0.1**, each with a test that fails today. See below.

## Known gaps in Draft 0.1

Adversarial testing of this draft found the gaps below. Closing any of them changes the
signed bytes or the request shape, so they are not fixed in the 0.1 line. Each is written
down as a test in [`tests/adversarial.rs`](./echo-authority-rust/tests/adversarial.rs) that
is marked `#[ignore]` and **fails** when run:

```sh
cd echo-authority-rust
cargo test --test adversarial -- --ignored
```

| Gap | What an attacker can do | What closing it needs |
|-----|-------------------------|-----------------------|
| No trust anchor | Sign a grant and a request with keys nobody registered; the verifier checks each signature against the key carried in the same message | Verifier-held trusted issuer keys; the grant commits to the subject's key |
| Budget keyed by a chosen id | Rename `authority_id` on a used-up grant and start a fresh budget | Derive the counter key from the signed grant |
| Unsigned human confirmation | Flip `human_confirmed` to `true` after signing | The human's signature over the exact invocation |
| Ambiguous signed bytes | Build two different grants that produce the same newline-joined preimage | Length-prefixed fields or canonical JSON |
| Floating-point amounts | Rust and JavaScript print large and tiny values differently, so the two sign different text | Integer minor units |
| No request freshness | Present an old signed invocation; `created` is never compared with the clock | A maximum invocation age |

Do not deploy Draft 0.1 as an enforcement boundary. An embedder that does must, at minimum,
pin issuer keys outside the request, own all counter and nonce state itself, and obtain human
confirmation through a channel the agent cannot write to.

Release 0.1.1 fixes what could be fixed without changing a single signed byte or reason code:
negative, NaN and infinite amounts are refused; a target resource must be literal and spelled
one way (no wildcard, no empty, `.` or `..` segment); a delegated grant may not drop human
confirmation, loosen revocation freshness, start earlier than its parent or re-enable
delegation; an unknown or missing field is a malformed request instead of a silent default;
signatures are verified strictly. The pinned vector digest is unchanged.

## Learn more

- [The protocol, with a live verifier](https://moneymusk.space/protocol) — run vectors in your browser
- [The Human Authority Model](https://moneymusk.space/model) — where authority comes from, and why it never begins with a machine
- [Verify it yourself](https://moneymusk.space/verify) — every claim we make, and the exact command that would falsify it

---

Draft 0.1. Fork it, audit it, break it.

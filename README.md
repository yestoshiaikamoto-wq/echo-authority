# Echo Authority Protocol — Rust reference implementation

**A human-rooted authority layer for autonomous systems.**

> AI can propose anything. It can only execute what a human has cryptographically authorized.

This repository is the Rust reference implementation of the [Echo Authority
Protocol](https://moneymusk.space/protocol), Draft 0.1. It exists to prove one thing: the
protocol is a *shared language*, not one company's server.

There are two independent implementations of the verifier — a TypeScript engine that runs the
live demos at [moneymusk.space/protocol](https://moneymusk.space/protocol), and the Rust code
in this repo. They share no code. Given the same Authority Object, the same Invocation, and the
same verifier state, they return the **identical verdict** on every conformance vector.

If two independent implementations agree, the standard is real. If they ever disagree, that
disagreement is the only bug that matters — please open an issue.

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
on). The rest prove attenuation: a delegated grant that widens *anything* cannot form.

You do not have to trust this README. Run the suite and break it.

## What's in here

| Crate | What it is |
|-------|-----------|
| [`echo-authority-core`](./echo-authority-rust) | The verifier: types, canonical serialization, the deterministic `border_check`, attenuation-only delegation, plus three binaries — `echo-border-control` (enforcement proxy), `echo-authority-cli` (keygen / mint / invoke / verify / attenuate), and `dump-vectors` (signed fixtures). Zero dependencies, pure `std`. |
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
- **Signatures in the test fixtures are modeled as opaque strings** in some vectors so the suite
  stays dependency-free and offline; the CLI and the WASM fixtures use real Ed25519.

## Learn more

- [The protocol, with a live verifier](https://moneymusk.space/protocol) — run vectors in your browser
- [The Human Authority Model](https://moneymusk.space/model) — where authority comes from, and why it never begins with a machine
- [Verify it yourself](https://moneymusk.space/verify) — every claim we make, and the exact command that would falsify it

---

Draft 0.1. Fork it, audit it, break it.

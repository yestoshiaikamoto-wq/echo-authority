# echo-authority-core

A **second, independent implementation** of the Echo Authority Protocol, Draft 0.1 — written in
Rust, with no shared code with the TypeScript reference at `/protocol`.

Its entire reason to exist: prove the protocol is a *shared language*, not one company's server.
Given the same Authority Object, the same Invocation, and the same verifier state, this Rust code
returns the **identical verdict** as the TypeScript engine. If two independent implementations
agree on every conformance vector, the standard is real.

## What's here

| File | What it is |
|------|-----------|
| `src/lib.rs` | The core: types, canonical serialization, the shared `evaluate_json` entry point, the deterministic `border_check`, and the attenuation-only `check_attenuation`. |
| `src/bin/echo-border-control.rs` | The reference enforcement proxy — pipe a request as JSON, get a verdict. Exit `0` on ALLOW, `1` on DENY. |
| `src/bin/echo-authority-cli.rs` | The developer + auditor tool — `keygen`, `mint`, `invoke`, `verify`, `attenuate`. Produce your own signed vectors and check them against any implementation. |
| `src/bin/dump-vectors.rs` | Emits genuinely-signed fixtures, consumed by the browser WASM demo at `/protocol`. |
| `tests/conformance.rs` | The hostile suite — 18 border vectors + attenuation + resource-subset, each asserting an exact reason code. |

A sibling crate, `../echo-authority-wasm`, compiles this same core to `wasm32-unknown-unknown`
so the identical verifier runs in the browser on `/protocol` — two independent runtimes, one verdict.

## Run it

```sh
cargo test          # run the full conformance suite (22 vectors)
cargo build --release
echo '{ "authority": {...}, "invocation": {...}, "state": {...} }' | ./target/release/echo-border-control
```

### Mint, sign, and verify your own — from the terminal

```sh
cli=./target/release/echo-authority-cli

# a key for the human issuer, and one for the acting agent
iss=$($cli keygen | jq -r .seed_hex)
sub=$($cli keygen | jq -r .seed_hex)

# the human mints + signs a bounded grant
auth=$(echo '{ ...authority fields... }' | $cli mint   --seed "$iss")

# the agent signs an invocation it wants to run under that grant
inv=$(echo  '{ ...invocation fields... }' | $cli invoke --seed "$sub")

# the border decides — exit 0 = ALLOW, exit 1 = DENY
echo "{\"authority\":$auth,\"invocation\":$inv,\"state\":{...}}" | $cli verify

# prove a delegated child never widens its parent — exit 0 = subset, 1 = not
echo '{"child":{...},"parent":{...}}' | $cli attenuate
```

Tamper with `amount` after `invoke` signs it and `verify` returns `BAD_INVOCATION_SIGNATURE` —
the signature was over the honest value, and the math notices.

## The verifier is deliberately boring

No model. No heuristics. No network. Twelve gates, in a fixed order, each returning the exact
reason it failed:

1. both signatures verify
2. subject matches
3. capability matches
4. resource is within the grant
5. value respects currency + per-action + total caps
6. inside the time window
7. uses budget remains
8. audience binds to this gateway
9. nonce is fresh (no replay)
10. not revoked, and revocation is fresh enough (offline changes the risk, never the rule)
11. capability is not in the never-grantable set
12. human confirmation present when the grant demands it

Only if all twelve pass does it ALLOW and mint an opaque receipt head — proof, never data.

## Attenuation

`check_attenuation(child, parent)` proves a delegated grant is a strict subset of its parent:
same capability, resource within, caps `≤`, expiry `≤`, uses `≤`, depth strictly less. A child
that widens *anything* cannot form. Power can only ever narrow as it flows down.

## The one sentence

> AI can propose anything. It can only execute what a human has cryptographically authorized.

This crate is the part that says *no*.

---

Draft 0.1. The protocol belongs to everyone — fork it, audit it, break it, and open an issue when
you find a vector where two implementations disagree. That disagreement is the only bug that
matters.

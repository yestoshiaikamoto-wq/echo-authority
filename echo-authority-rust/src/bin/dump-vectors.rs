//! dump-vectors — emits a spread of genuinely-signed request fixtures as a JSON array.
//!
//! These are consumed by the browser demo at /protocol: the SAME signed requests are fed to
//! the Rust verifier compiled to WebAssembly, proving the reference implementation runs in the
//! browser and returns the canonical reason code for each. Deterministic (fixed keys).

use echo_authority_core::{
    authority_id, canonical_authority, canonical_invocation, AuthorityObject, Constraints, Delegation,
    Invocation, Revocation, Scope,
};
use ed25519_dalek::{Signer, SigningKey};

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        out.push(A[(b[0] >> 2) as usize] as char);
        out.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { A[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(b[2] & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}
fn subject_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn sign_auth(a: &mut AuthorityObject) {
    let k = issuer_key();
    a.issuer_pub = b64(&k.verifying_key().to_bytes());
    a.sig = b64(&k.sign(canonical_authority(a).as_bytes()).to_bytes());
}
fn sign_inv(i: &mut Invocation) {
    let k = subject_key();
    i.subject_pub = b64(&k.verifying_key().to_bytes());
    i.sig = b64(&k.sign(canonical_invocation(i).as_bytes()).to_bytes());
}

fn sign_pair(a: &mut AuthorityObject, i: &mut Invocation) {
    sign_auth(a);
    i.authority_id = authority_id(a);
    sign_inv(i);
}

fn base_authority() -> AuthorityObject {
    AuthorityObject {
        issuer: "did:echo:human:0x427".into(),
        subject: "agent:studio:booking-agent".into(),
        capability: "payment.execute".into(),
        resource: "merchant:studio-881".into(),
        scope: Scope { currency: Some("EUR".into()), max_per_action_minor: 4_000, max_total_minor: 20_000 },
        constraints: Constraints {
            not_before: 0,
            expires: 4_102_444_800,
            max_uses: 5,
            require_human_confirmation: false,
        },
        delegation: Delegation { allowed: false, max_depth: 0 },
        revocation: Revocation {
            method: "revocation-list".into(),
            id: "rev-8821".into(),
            freshness_required_sec: 30,
        },
        issuer_pub: String::new(),
        subject_pub: b64(&subject_key().verifying_key().to_bytes()),
        sig: String::new(),
    }
}

fn base_invocation() -> Invocation {
    Invocation {
        authority_id: "auth-1".into(),
        invocation_id: "inv-1".into(),
        subject: "agent:studio:booking-agent".into(),
        capability: "payment.execute".into(),
        resource: "merchant:studio-881".into(),
        amount_minor: 4_000,
        currency: Some("EUR".into()),
        audience: "echo-pay-gateway".into(),
        nonce: "n-1".into(),
        created: 1000,
        human_confirmed: false,
        subject_pub: String::new(),
        sig: String::new(),
    }
}

struct State {
    now: i64,
    online: bool,
    used_nonces: Vec<&'static str>,
}
fn default_state() -> State {
    State { now: 1000, online: true, used_nonces: vec![] }
}

fn state_json(s: &State) -> String {
    let nonces = s
        .used_nonces
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"now\":{},\"audience\":\"echo-pay-gateway\",\"online\":{},\"revocation_age_sec\":2,\"used_nonces\":[{}],\"offline_limit_minor\":2000,\"max_clock_skew_sec\":30,\"max_invocation_age_sec\":300,\"trusted_issuers\":{{\"did:echo:human:0x427\":\"{}\"}}}}",
        s.now, s.online, nonces, b64(&issuer_key().verifying_key().to_bytes())
    )
}

fn emit(
    out: &mut Vec<String>,
    name: &str,
    title: &str,
    expect: &str,
    a: AuthorityObject,
    i: Invocation,
    s: State,
) {
    let auth = serde_json::to_string(&a).unwrap();
    let inv = serde_json::to_string(&i).unwrap();
    out.push(format!(
        "{{\"name\":\"{}\",\"title\":\"{}\",\"expect\":\"{}\",\"request\":{{\"authority\":{},\"invocation\":{},\"state\":{}}}}}",
        name, title, expect, auth, inv, state_json(&s)
    ));
}

fn main() {
    let mut out: Vec<String> = Vec::new();

    // 1. a clean, bounded payment within every limit
    {
        let mut a = base_authority();
        let mut i = base_invocation();
        sign_pair(&mut a, &mut i);
        emit(&mut out, "ok", "Pay EUR40 to the granted merchant", "OK", a, i, default_state());
    }

    // 2. one cent over the per-action cap
    {
        let mut a = base_authority();
        let mut i = base_invocation();
        i.amount_minor = 4_001;
        sign_pair(&mut a, &mut i);
        emit(&mut out, "value", "Pay EUR41 — over the per-action cap", "VALUE_LIMIT_EXCEEDED", a, i, default_state());
    }

    // 3. a different merchant than the grant names
    {
        let mut a = base_authority();
        let mut i = base_invocation();
        i.resource = "merchant:rogue-shop".into();
        sign_pair(&mut a, &mut i);
        emit(&mut out, "resource", "Pay a merchant outside the grant", "RESOURCE_MISMATCH", a, i, default_state());
    }

    // 4. the grant has expired
    {
        let mut a = base_authority();
        a.constraints.expires = 900;
        let mut i = base_invocation();
        sign_pair(&mut a, &mut i);
        emit(&mut out, "expired", "Use a grant past its expiry", "EXPIRED", a, i, default_state());
    }

    // 5. the invocation nonce was already spent
    {
        let mut a = base_authority();
        let mut i = base_invocation();
        sign_pair(&mut a, &mut i);
        let mut s = default_state();
        s.used_nonces = vec!["n-1"];
        emit(&mut out, "replay", "Replay a used invocation", "NONCE_REPLAY", a, i, s);
    }

    // 6. a capability no one may ever grant
    {
        let mut a = base_authority();
        a.capability = "root.export".into();
        a.scope.currency = None;
        let mut i = base_invocation();
        i.capability = "root.export".into();
        i.amount_minor = 0;
        i.currency = None;
        sign_pair(&mut a, &mut i);
        emit(&mut out, "forbidden", "Ask to export the root key", "FORBIDDEN_CAPABILITY", a, i, default_state());
    }

    // 7. a destructive action that demands human confirmation it did not get
    {
        let mut a = base_authority();
        a.constraints.require_human_confirmation = true;
        a.scope.currency = None;
        let mut i = base_invocation();
        i.amount_minor = 0;
        i.currency = None;
        i.human_confirmed = false;
        sign_pair(&mut a, &mut i);
        emit(&mut out, "human", "Act without the required human confirmation", "HUMAN_CONFIRMATION_REQUIRED", a, i, default_state());
    }

    // 8. the amount was tampered AFTER signing — the signature no longer matches
    {
        let mut a = base_authority();
        let mut i = base_invocation();
        sign_pair(&mut a, &mut i);
        i.amount_minor = 500; // tamper in transit; sig was over 4,000
        emit(&mut out, "tampered", "Tamper with the amount in transit", "BAD_INVOCATION_SIGNATURE", a, i, default_state());
    }

    println!("[\n{}\n]", out.join(",\n"));
}

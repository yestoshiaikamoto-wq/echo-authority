//! Hostile conformance suite for echo-authority-core.
//!
//! Each test mints a well-formed, correctly-signed Authority Object + Invocation, then bends
//! exactly ONE thing and asserts the exact reason Border Control must return. These mirror the
//! live vectors at /protocol — a conformant verifier in ANY language must produce identical
//! (decision, reason) pairs. Run with `cargo test`.

use echo_authority_core::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

// --- signing helpers (tests sign for real, so BAD_*_SIGNATURE is genuinely tested) ---

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn canonical_authority(a: &AuthorityObject) -> String {
    // must match the crate's private canonical form exactly
    format!(
        "ECHO-AUTHORITY\nv0.1\n{}\n{}\n{}\n{}\n{}|{}|{}\n{}|{}|{}|{}\n{}|{}\n{}|{}|{}",
        a.issuer, a.subject, a.capability, a.resource,
        a.scope.currency.clone().unwrap_or_default(), a.scope.max_per_action, a.scope.max_total,
        a.constraints.not_before, a.constraints.expires, a.constraints.max_uses,
        a.constraints.require_human_confirmation,
        a.delegation.allowed, a.delegation.max_depth,
        a.revocation.method, a.revocation.id, a.revocation.freshness_required_sec,
    )
}

fn canonical_invocation(i: &Invocation) -> String {
    format!(
        "ECHO-INVOCATION\nv0.1\n{}\n{}\n{}\n{}\n{}\n{}|{}\n{}\n{}\n{}",
        i.authority_id, i.invocation_id, i.subject, i.capability, i.resource,
        i.amount, i.currency.clone().unwrap_or_default(), i.audience, i.nonce, i.created,
    )
}

struct Fixture {
    authority: AuthorityObject,
    invocation: Invocation,
    state: VerifierState,
}

/// A baseline that ALLOWs. Each test mutates it via the closure before signing.
fn baseline(mutate: impl FnOnce(&mut AuthorityObject, &mut Invocation, &mut VerifierState)) -> Fixture {
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let subject = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_pub = b64(issuer.verifying_key().as_bytes());
    let subject_pub = b64(subject.verifying_key().as_bytes());

    let mut authority = AuthorityObject {
        issuer: "did:echo:human:0x427".into(),
        subject: "agent:studio:booking-agent".into(),
        capability: "payment.execute".into(),
        resource: "merchant:studio-881".into(),
        scope: Scope { currency: Some("EUR".into()), max_per_action: 40.0, max_total: 200.0 },
        constraints: Constraints { not_before: 1_000, expires: 100_000, max_uses: 5, require_human_confirmation: false },
        delegation: Delegation { allowed: false, max_depth: 0 },
        revocation: Revocation { method: "revocation-list".into(), id: "rev-8821".into(), freshness_required_sec: 30 },
        issuer_pub,
        sig: String::new(),
    };
    let mut invocation = Invocation {
        authority_id: "auth-1".into(),
        invocation_id: "inv-1".into(),
        subject: "agent:studio:booking-agent".into(),
        capability: "payment.execute".into(),
        resource: "merchant:studio-881".into(),
        amount: 40.0,
        currency: Some("EUR".into()),
        audience: "echo-pay-gateway".into(),
        nonce: "nonce-1".into(),
        created: 5_000,
        human_confirmed: false,
        subject_pub,
        sig: String::new(),
    };
    let mut state = VerifierState {
        now: 5_000,
        audience: "echo-pay-gateway".into(),
        online: true,
        revocation_age_sec: 2,
        revoked_ids: BTreeSet::new(),
        used_nonces: BTreeSet::new(),
        uses: BTreeMap::new(),
        spent_total: BTreeMap::new(),
        offline_limit: 20.0,
    };

    mutate(&mut authority, &mut invocation, &mut state);

    // sign AFTER mutation (except tamper tests, which re-tamper below)
    authority.sig = b64(&issuer.sign(canonical_authority(&authority).as_bytes()).to_bytes());
    invocation.sig = b64(&subject.sign(canonical_invocation(&invocation).as_bytes()).to_bytes());

    Fixture { authority, invocation, state }
}

fn run(f: &Fixture) -> BorderResult {
    border_check(&f.authority, &f.invocation, &f.state)
}

macro_rules! vector {
    ($name:ident, $reason:expr, $mutate:expr) => {
        #[test]
        fn $name() {
            let f = baseline($mutate);
            let r = run(&f);
            assert_eq!(r.reason, $reason, "expected {:?}, got {:?}", $reason, r.reason);
            if $reason == Reason::Ok {
                assert_eq!(r.decision, Decision::Allow);
                assert!(r.receipt.is_some(), "ALLOW must produce a receipt");
            } else {
                assert_eq!(r.decision, Decision::Deny);
                assert!(r.receipt.is_none(), "DENY must not produce a receipt");
            }
        }
    };
}

vector!(v01_ok, Reason::Ok, |_a, _i, _s| {});
vector!(v02_value_cap, Reason::ValueLimitExceeded, |_a, i, _s| { i.amount = 40.01; });
vector!(v03_total_cap, Reason::TotalLimitExceeded, |_a, i, s| { i.amount = 40.0; s.spent_total.insert("auth-1".into(), 180.0); });
vector!(v04_currency, Reason::CurrencyMismatch, |_a, i, _s| { i.currency = Some("USD".into()); });
vector!(v05_resource, Reason::ResourceMismatch, |_a, i, _s| { i.resource = "merchant:other-999".into(); });
vector!(v06_capability, Reason::CapabilityMismatch, |_a, i, _s| { i.capability = "payment.refund".into(); });
vector!(v07_subject, Reason::SubjectMismatch, |_a, i, _s| { i.subject = "agent:rogue".into(); });
vector!(v08_expired, Reason::Expired, |_a, _i, s| { s.now = 200_000; });
vector!(v09_not_yet, Reason::NotYetValid, |_a, _i, s| { s.now = 500; });
vector!(v10_max_uses, Reason::MaxUsesExceeded, |_a, _i, s| { s.uses.insert("auth-1".into(), 5); });
vector!(v11_replay, Reason::NonceReplay, |_a, i, s| { s.used_nonces.insert(i.nonce.clone()); });
vector!(v12_audience, Reason::AudienceMismatch, |_a, i, _s| { i.audience = "some-other-gateway".into(); });
vector!(v13_revoked, Reason::Revoked, |a, _i, s| { s.revoked_ids.insert(a.revocation.id.clone()); });
vector!(v14_stale, Reason::RevocationStale, |_a, _i, s| { s.online = false; s.revocation_age_sec = 999; });
vector!(v15_offline_value, Reason::OfflineValueExceeded, |_a, _i, s| { s.online = false; s.revocation_age_sec = 2; s.offline_limit = 20.0; });
vector!(v16_human, Reason::HumanConfirmationRequired, |a, _i, _s| { a.constraints.require_human_confirmation = true; });
vector!(v17_forbidden, Reason::ForbiddenCapability, |a, i, _s| { a.capability = "export-root-key".into(); i.capability = "export-root-key".into(); a.scope.max_per_action = 0.0; i.amount = 0.0; });

// A tamper test: sign a valid invocation, then mutate the amount AFTER signing.
#[test]
fn v18_tampered_invocation() {
    let mut f = baseline(|_a, _i, _s| {});
    f.invocation.amount = 39.0; // signature no longer covers this
    let r = run(&f);
    assert_eq!(r.reason, Reason::BadInvocationSignature);
    assert_eq!(r.decision, Decision::Deny);
}

// --- attenuation: a child may narrow, never widen ---

fn issue(cap: &str, resource: &str, per: f64, expires: i64, uses: u64, depth: u32, allowed: bool) -> AuthorityObject {
    let k = SigningKey::from_bytes(&[3u8; 32]);
    let mut a = AuthorityObject {
        issuer: "issuer".into(), subject: "subject".into(),
        capability: cap.into(), resource: resource.into(),
        scope: Scope { currency: Some("EUR".into()), max_per_action: per, max_total: per * 5.0 },
        constraints: Constraints { not_before: 0, expires, max_uses: uses, require_human_confirmation: false },
        delegation: Delegation { allowed, max_depth: depth },
        revocation: Revocation { method: "revocation-list".into(), id: "r".into(), freshness_required_sec: 30 },
        issuer_pub: b64(k.verifying_key().as_bytes()), sig: String::new(),
    };
    a.sig = b64(&k.sign(b"x").to_bytes());
    a
}

#[test]
fn attenuation_narrow_is_subset() {
    let parent = issue("data.read", "vault/public/*", 10.0, 100_000, 10, 1, true);
    let child = issue("data.read", "vault/public/report-7", 5.0, 50_000, 1, 0, false);
    let r = check_attenuation(&child, &parent);
    assert!(r.ok, "a strictly-narrower child must be a subset: {:?}", r.violations);
}

#[test]
fn attenuation_widen_resource_rejected() {
    let parent = issue("data.read", "vault/public/*", 10.0, 100_000, 10, 1, true);
    let child = issue("data.read", "vault/*", 5.0, 50_000, 1, 0, false);
    let r = check_attenuation(&child, &parent);
    assert!(!r.ok);
    assert!(r.violations.iter().any(|v| v.contains("resource is not within")));
}

#[test]
fn attenuation_raise_cap_rejected() {
    let parent = issue("payment.execute", "merchant:x", 40.0, 100_000, 10, 1, true);
    let child = issue("payment.execute", "merchant:x", 400.0, 50_000, 1, 0, false);
    let r = check_attenuation(&child, &parent);
    assert!(!r.ok);
    assert!(r.violations.iter().any(|v| v.contains("max_per_action exceeds parent")));
}

#[test]
fn resource_within_rules() {
    assert!(resource_within("vault/public/a", "vault/public/*"));
    assert!(resource_within("vault/public/a", "vault/public"));
    assert!(resource_within("merchant:x", "merchant:x"));
    assert!(!resource_within("vault/private/a", "vault/public/*"));
    assert!(!resource_within("merchant:y", "merchant:x"));
}

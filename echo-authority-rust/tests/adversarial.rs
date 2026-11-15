//! Adversarial regression suite.
//!
//! Each test is an attack that a deterministic authority verifier must refuse. Tests that
//! pass are fixed in this crate. Tests marked `#[ignore]` are OPEN: closing them changes the
//! signed bytes or the request shape, so they belong to the next protocol version. Run the
//! open ones with `cargo test --test adversarial -- --ignored` — every one that fails is a
//! live gap in Draft 0.1.

use echo_authority_core::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

type Parts = (AuthorityObject, Invocation, VerifierState);

/// A request that ALLOWs, signed by the given seeds after `mutate` runs.
fn signed(issuer_seed: u8, subject_seed: u8, mutate: impl FnOnce(&mut AuthorityObject, &mut Invocation, &mut VerifierState)) -> Parts {
    let ik = SigningKey::from_bytes(&[issuer_seed; 32]);
    let sk = SigningKey::from_bytes(&[subject_seed; 32]);
    let mut a = AuthorityObject {
        issuer: "did:echo:human:0x427".into(),
        subject: "agent:studio:booking-agent".into(),
        capability: "payment.execute".into(),
        resource: "merchant:studio-881".into(),
        scope: Scope { currency: Some("EUR".into()), max_per_action: 40.0, max_total: 200.0 },
        constraints: Constraints { not_before: 1_000, expires: 100_000, max_uses: 5, require_human_confirmation: false },
        delegation: Delegation { allowed: false, max_depth: 0 },
        revocation: Revocation { method: "revocation-list".into(), id: "rev-8821".into(), freshness_required_sec: 30 },
        issuer_pub: b64(ik.verifying_key().as_bytes()),
        sig: String::new(),
    };
    let mut i = Invocation {
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
        subject_pub: b64(sk.verifying_key().as_bytes()),
        sig: String::new(),
    };
    let mut s = VerifierState {
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
    mutate(&mut a, &mut i, &mut s);
    a.sig = b64(&ik.sign(canonical_authority(&a).as_bytes()).to_bytes());
    i.sig = b64(&sk.sign(canonical_invocation(&i).as_bytes()).to_bytes());
    (a, i, s)
}

fn decide((a, i, s): &Parts) -> BorderResult {
    border_check(a, i, s)
}

// ---------------------------------------------------------------------------
// FIXED in 0.1.1 — these must stay green. No reason code was added: Draft 0.1's
// vocabulary is unchanged, so other implementations of the draft need no new strings.
// ---------------------------------------------------------------------------

#[test]
fn a01_negative_amount_is_refused() {
    let r = decide(&signed(7, 9, |_a, i, s| {
        i.amount = -5000.0;
        i.currency = Some("USD".into());
        s.spent_total.insert("auth-1".into(), 200.0);
    }));
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.reason, Reason::ValueLimitExceeded);
}

#[test]
fn a02_nan_and_infinite_amounts_are_refused() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let r = decide(&signed(7, 9, |_a, i, _s| i.amount = bad));
        assert_eq!(r.reason, Reason::ValueLimitExceeded, "amount {bad}");
    }
}

#[test]
fn a03_negative_cap_is_refused() {
    let r = decide(&signed(7, 9, |a, i, _s| {
        a.scope.max_total = -1.0;
        i.amount = 0.0;
    }));
    assert_eq!(r.reason, Reason::ValueLimitExceeded);
}

#[test]
fn a04_resource_traversal_is_refused() {
    assert!(!resource_within("vault/public/../private/keys", "vault/public/*"));
    assert!(!resource_within("vault/public/./../private", "vault/public"));
    for stray in ["merchant:studio-881/", "/merchant:studio-881", "merchant:studio-881//x", "merchant:studio-881/."] {
        let r = decide(&signed(7, 9, |_a, i, _s| i.resource = stray.into()));
        assert_eq!(r.reason, Reason::ResourceMismatch, "{stray}");
    }
    let r = decide(&signed(7, 9, |a, i, _s| {
        a.resource = "vault/public/*".into();
        i.resource = "vault/public/../private/keys".into();
    }));
    assert_eq!(r.reason, Reason::ResourceMismatch);
}

#[test]
fn a05_invocation_cannot_target_a_wildcard() {
    let r = decide(&signed(7, 9, |a, i, _s| {
        a.resource = "vault/public/*".into();
        i.resource = "vault/public/*".into();
    }));
    assert_eq!(r.reason, Reason::ResourceMismatch);
}

fn grant(f: impl FnOnce(&mut AuthorityObject)) -> AuthorityObject {
    let (mut a, _, _) = signed(7, 9, |_, _, _| {});
    f(&mut a);
    a
}

#[test]
fn a06_child_cannot_drop_human_confirmation() {
    let parent = grant(|a| {
        a.delegation = Delegation { allowed: true, max_depth: 1 };
        a.constraints.require_human_confirmation = true;
    });
    let child = grant(|a| a.constraints.require_human_confirmation = false);
    assert!(!check_attenuation(&child, &parent).ok);
}

#[test]
fn a07_child_cannot_loosen_revocation_freshness() {
    let parent = grant(|a| a.delegation = Delegation { allowed: true, max_depth: 1 });
    let child = grant(|a| a.revocation.freshness_required_sec = 999_999);
    assert!(!check_attenuation(&child, &parent).ok);
}

#[test]
fn a08_child_cannot_start_before_parent() {
    let parent = grant(|a| a.delegation = Delegation { allowed: true, max_depth: 1 });
    let child = grant(|a| a.constraints.not_before = 0);
    assert!(!check_attenuation(&child, &parent).ok);
}

#[test]
fn a09_misspelled_safety_field_is_malformed_not_false() {
    let (a, i, _) = signed(7, 9, |_, _, _| {});
    let mut doc = serde_json::json!({
        "authority": a, "invocation": i,
        "state": { "now": 5000, "audience": "echo-pay-gateway", "online": true }
    });
    let c = doc["authority"]["constraints"].as_object_mut().unwrap();
    c.remove("require_human_confirmation");
    c.insert("require_human_confirmtion".into(), true.into());
    let v = evaluate_json(&doc.to_string());
    assert!(!v.allow);
    assert!(v.json.contains("MALFORMED_REQUEST"));
}

#[test]
fn a10_small_order_issuer_key_is_refused() {
    // The all-zero-ish identity encoding: a weak key under which forged signatures can verify
    // in non-strict mode. Strict verification must reject it outright.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let (mut a, i, s) = signed(7, 9, |_, _, _| {});
    a.issuer_pub = b64(&identity);
    a.sig = b64(&[0u8; 64]);
    assert_eq!(border_check(&a, &i, &s).reason, Reason::BadAuthoritySignature);
}

// ---------------------------------------------------------------------------
// OPEN in Draft 0.1 — each needs a change to the signed bytes or the request shape.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "OPEN: verifier has no trust anchor; keys are taken from the message being verified"]
fn o01_unregistered_keys_must_not_mint_authority() {
    // Seeds 200/201 belong to nobody. Fix: VerifierState carries trusted issuer keys, and the
    // Authority Object commits to the subject's public key inside its signed bytes.
    let r = decide(&signed(200, 201, |_, _, _| {}));
    assert_eq!(r.decision, Decision::Deny);
}

#[test]
#[ignore = "OPEN: usage counters are keyed by an id the invoking agent chooses"]
fn o02_renaming_authority_id_must_not_reset_the_budget() {
    // Fix: derive the id from the grant (e.g. SHA-256 of its canonical bytes) and reject an
    // invocation whose authority_id does not equal it.
    let r = decide(&signed(7, 9, |_a, i, s| {
        s.uses.insert("auth-1".into(), 5);
        s.spent_total.insert("auth-1".into(), 200.0);
        i.authority_id = "auth-2".into();
    }));
    assert_eq!(r.decision, Decision::Deny);
}

#[test]
#[ignore = "OPEN: human_confirmed is an unsigned boolean"]
fn o03_flipping_human_confirmed_after_signing_must_fail() {
    // Fix: replace the flag with a signature from the human's key over this exact invocation.
    let (a, mut i, s) = signed(7, 9, |a, _, _| a.constraints.require_human_confirmation = true);
    i.human_confirmed = true;
    assert_eq!(border_check(&a, &i, &s).decision, Decision::Deny);
}

#[test]
#[ignore = "OPEN: canonical form joins fields with unescaped newlines and pipes"]
fn o04_distinct_grants_must_not_share_signed_bytes() {
    // Fix: length-prefix every field, or sign RFC 8785 canonical JSON.
    let x = grant(|a| {
        a.subject = "agent:x\npayment.execute".into();
        a.capability = "merchant:studio-881".into();
        a.resource = "tail".into();
    });
    let y = grant(|a| {
        a.subject = "agent:x".into();
        a.capability = "payment.execute\nmerchant:studio-881".into();
        a.resource = "tail".into();
    });
    assert_ne!(canonical_authority(&x), canonical_authority(&y));
}

#[test]
#[ignore = "OPEN: amounts are floats; Rust and JavaScript print large/small values differently"]
fn o05_amount_canonical_text_must_match_other_runtimes() {
    // JavaScript prints 1e21 as "1e+21" and 1e-7 as "1e-7". Fix: integer minor units.
    let (_, i, _) = signed(7, 9, |_a, i, _s| i.amount = 1e21);
    assert!(canonical_invocation(&i).contains("1e+21"));
}

#[test]
#[ignore = "OPEN: an expired-looking request has no freshness bound on `created`"]
fn o06_stale_invocation_should_be_refused() {
    // Fix: reject when state.now - invocation.created exceeds a verifier-set maximum age.
    let r = decide(&signed(7, 9, |_a, i, s| {
        i.created = 1_000;
        s.now = 99_999;
    }));
    assert_eq!(r.decision, Decision::Deny);
}

//! Adversarial conformance tests for protocol v0.2.

use echo_authority_core::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn sign_authority(a: &mut AuthorityObject, key: &SigningKey) {
    a.issuer_pub = b64(key.verifying_key().as_bytes());
    a.sig = b64(&key.sign(canonical_authority(a).as_bytes()).to_bytes());
}

fn sign_invocation(i: &mut Invocation, key: &SigningKey) {
    i.subject_pub = b64(key.verifying_key().as_bytes());
    i.sig = b64(&key.sign(canonical_invocation(i).as_bytes()).to_bytes());
}

struct Fixture {
    authority: AuthorityObject,
    invocation: Invocation,
    state: VerifierState,
    issuer_key: SigningKey,
    subject_key: SigningKey,
}

fn fixture() -> Fixture {
    let issuer_key = SigningKey::from_bytes(&[7u8; 32]);
    let subject_key = SigningKey::from_bytes(&[9u8; 32]);
    let issuer_pub = b64(issuer_key.verifying_key().as_bytes());
    let subject_pub = b64(subject_key.verifying_key().as_bytes());
    let mut authority = AuthorityObject {
        issuer: "did:echo:human:427".into(), subject: "agent:booking".into(),
        capability: "payment.execute".into(), resource: "merchant/studio-881".into(),
        scope: Scope { currency: Some("EUR".into()), max_per_action_minor: 4_000, max_total_minor: 20_000 },
        constraints: Constraints { not_before: 1_000, expires: 100_000, max_uses: 5, require_human_confirmation: false },
        delegation: Delegation { allowed: false, max_depth: 0 },
        revocation: Revocation { method: "revocation-list".into(), id: "rev-8821".into(), freshness_required_sec: 30 },
        issuer_pub: issuer_pub.clone(), subject_pub: subject_pub.clone(), sig: String::new(),
    };
    sign_authority(&mut authority, &issuer_key);
    let mut invocation = Invocation {
        authority_id: authority_id(&authority), invocation_id: "inv-1".into(),
        subject: authority.subject.clone(), capability: authority.capability.clone(),
        resource: authority.resource.clone(), amount_minor: 4_000, currency: Some("EUR".into()),
        audience: "echo-pay-gateway".into(), nonce: "nonce-1".into(), created: 5_000,
        human_confirmed: false, subject_pub, sig: String::new(),
    };
    sign_invocation(&mut invocation, &subject_key);
    let mut trusted_issuers = BTreeMap::new();
    trusted_issuers.insert(authority.issuer.clone(), issuer_pub);
    let state = VerifierState {
        now: 5_000, audience: "echo-pay-gateway".into(), online: true,
        revocation_age_sec: 2, revoked_ids: BTreeSet::new(), used_nonces: BTreeSet::new(),
        uses: BTreeMap::new(), spent_total_minor: BTreeMap::new(), offline_limit_minor: 2_000,
        max_clock_skew_sec: 30, max_invocation_age_sec: 300, trusted_issuers,
        previous_receipt_head: None,
    };
    Fixture { authority, invocation, state, issuer_key, subject_key }
}

fn resign_authority_and_invocation(f: &mut Fixture) {
    sign_authority(&mut f.authority, &f.issuer_key);
    f.invocation.authority_id = authority_id(&f.authority);
    sign_invocation(&mut f.invocation, &f.subject_key);
}

fn resign_invocation(f: &mut Fixture) { sign_invocation(&mut f.invocation, &f.subject_key); }

#[test] fn valid_request_allows() { assert_eq!(border_check(&fixture().authority, &fixture().invocation, &fixture().state).reason, Reason::Ok); }

#[test]
fn self_asserted_issuer_key_is_rejected() {
    let mut f = fixture();
    let rogue = SigningKey::from_bytes(&[33u8; 32]);
    sign_authority(&mut f.authority, &rogue);
    f.invocation.authority_id = authority_id(&f.authority);
    sign_invocation(&mut f.invocation, &f.subject_key);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::UntrustedIssuer);
}

#[test]
fn substituted_subject_key_is_rejected() {
    let mut f = fixture();
    let rogue = SigningKey::from_bytes(&[44u8; 32]);
    sign_invocation(&mut f.invocation, &rogue);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::SubjectKeyMismatch);
}

#[test]
fn invented_authority_id_cannot_reset_accounting() {
    let mut f = fixture();
    f.invocation.authority_id = "fresh-accounting-bucket".into();
    resign_invocation(&mut f);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::AuthorityIdMismatch);
}

#[test]
fn human_confirmation_is_covered_by_signature() {
    let mut f = fixture();
    f.authority.constraints.require_human_confirmation = true;
    resign_authority_and_invocation(&mut f);
    f.invocation.human_confirmed = true;
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::BadInvocationSignature);
}

#[test]
fn protocol_forbidden_names_are_rejected() {
    for cap in FORBIDDEN_CAPS {
        let mut f = fixture();
        f.authority.capability = (*cap).into();
        f.invocation.capability = (*cap).into();
        resign_authority_and_invocation(&mut f);
        assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::ForbiddenCapability, "{cap}");
    }
}

#[test]
fn value_and_total_limits_are_enforced_in_minor_units() {
    let mut f = fixture();
    f.invocation.amount_minor = 4_001; resign_invocation(&mut f);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::ValueLimitExceeded);
    f.invocation.amount_minor = 4_000; resign_invocation(&mut f);
    f.state.spent_total_minor.insert(f.invocation.authority_id.clone(), 18_000);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::TotalLimitExceeded);
}

#[test]
fn zero_value_with_currency_is_rejected() {
    let mut f = fixture(); f.invocation.amount_minor = 0; resign_invocation(&mut f);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::InvalidAmount);
}

#[test]
fn stale_future_and_pregrant_invocations_are_rejected() {
    for created in [500, 4_000, 6_000] {
        let mut f = fixture(); f.invocation.created = created; resign_invocation(&mut f);
        assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::InvocationTimeInvalid);
    }
}

#[test]
fn currency_resource_subject_capability_and_audience_are_bound() {
    let cases: Vec<(fn(&mut Fixture), Reason)> = vec![
        (|f| f.invocation.currency = Some("USD".into()), Reason::CurrencyMismatch),
        (|f| f.invocation.resource = "merchant/other".into(), Reason::ResourceMismatch),
        (|f| f.invocation.subject = "agent:rogue".into(), Reason::SubjectMismatch),
        (|f| f.invocation.capability = "payment.refund".into(), Reason::CapabilityMismatch),
        (|f| f.invocation.audience = "other-gateway".into(), Reason::AudienceMismatch),
    ];
    for (mutate, expected) in cases {
        let mut f = fixture(); mutate(&mut f); resign_invocation(&mut f);
        assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, expected);
    }
}

#[test]
fn expiry_use_replay_revocation_and_offline_rules_hold() {
    let mut f = fixture(); f.state.now = 100_000;
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::Expired);
    let mut f = fixture(); f.state.uses.insert(f.invocation.authority_id.clone(), 5);
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::MaxUsesExceeded);
    let mut f = fixture(); f.state.used_nonces.insert(f.invocation.nonce.clone());
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::NonceReplay);
    let mut f = fixture(); f.state.revoked_ids.insert(f.authority.revocation.id.clone());
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::Revoked);
    let mut f = fixture(); f.state.online = false; f.state.revocation_age_sec = 31;
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::RevocationStale);
    let mut f = fixture(); f.state.online = false;
    assert_eq!(border_check(&f.authority, &f.invocation, &f.state).reason, Reason::OfflineValueExceeded);
}

#[test]
fn authorization_consumes_state_and_chains_receipts() {
    let mut f = fixture();
    let first = authorize_and_record(&f.authority, &f.invocation, &mut f.state);
    assert_eq!(first.reason, Reason::Ok);
    assert!(f.state.used_nonces.contains("nonce-1"));
    assert_eq!(f.state.uses[&f.invocation.authority_id], 1);
    assert_eq!(f.state.spent_total_minor[&f.invocation.authority_id], 4_000);
    assert!(f.state.previous_receipt_head.is_some());
    assert_eq!(authorize_and_record(&f.authority, &f.invocation, &mut f.state).reason, Reason::NonceReplay);
}

#[test]
fn receipt_is_signed_and_gateway_key_is_pinned() {
    let f = fixture();
    let claims = border_check(&f.authority, &f.invocation, &f.state).receipt.unwrap();
    let gateway = SigningKey::from_bytes(&[55u8; 32]);
    let receipt = sign_receipt(claims, "gateway:primary", &gateway);
    let mut trusted = BTreeMap::new();
    trusted.insert(receipt.gateway_id.clone(), receipt.gateway_pub.clone());
    assert!(verify_signed_receipt(&receipt, &trusted));
    trusted.insert("gateway:primary".into(), b64(SigningKey::from_bytes(&[56u8; 32]).verifying_key().as_bytes()));
    assert!(!verify_signed_receipt(&receipt, &trusted));
}

#[test]
fn receipt_tampering_breaks_signature() {
    let f = fixture();
    let claims = border_check(&f.authority, &f.invocation, &f.state).receipt.unwrap();
    let gateway = SigningKey::from_bytes(&[55u8; 32]);
    let mut receipt = sign_receipt(claims, "gateway:primary", &gateway);
    let mut trusted = BTreeMap::new(); trusted.insert(receipt.gateway_id.clone(), receipt.gateway_pub.clone());
    receipt.claims.amount_minor += 1;
    assert!(!verify_signed_receipt(&receipt, &trusted));
}

#[test]
fn canonical_encoding_has_no_newline_boundary_collision() {
    let mut a = fixture().authority; let mut b = a.clone();
    a.issuer = "human\nagent".into(); a.subject = "worker".into();
    b.issuer = "human".into(); b.subject = "agent\nworker".into();
    assert_ne!(canonical_authority(&a), canonical_authority(&b));
}

#[test]
fn resource_traversal_and_false_prefixes_are_rejected() {
    assert!(resource_within("vault/public/report", "vault/public"));
    assert!(!resource_within("vault/publicity/report", "vault/public"));
    assert!(!resource_within("vault/public/../private/key", "vault/public"));
}

fn delegation_pair() -> (AuthorityObject, AuthorityObject, SigningKey, SigningKey) {
    let root = SigningKey::from_bytes(&[61u8; 32]);
    let agent = SigningKey::from_bytes(&[62u8; 32]);
    let worker = SigningKey::from_bytes(&[63u8; 32]);
    let mut parent = AuthorityObject {
        issuer: "human".into(), subject: "agent".into(), capability: "data.read".into(),
        resource: "vault/public/*".into(), scope: Scope { currency: None, max_per_action_minor: 0, max_total_minor: 0 },
        constraints: Constraints { not_before: 1_000, expires: 10_000, max_uses: 10, require_human_confirmation: true },
        delegation: Delegation { allowed: true, max_depth: 2 },
        revocation: Revocation { method: "list".into(), id: "root-rev".into(), freshness_required_sec: 30 },
        issuer_pub: String::new(), subject_pub: b64(agent.verifying_key().as_bytes()), sig: String::new(),
    };
    sign_authority(&mut parent, &root);
    let mut child = AuthorityObject {
        issuer: "agent".into(), subject: "worker".into(), capability: "data.read".into(),
        resource: "vault/public/report".into(), scope: Scope { currency: None, max_per_action_minor: 0, max_total_minor: 0 },
        constraints: Constraints { not_before: 2_000, expires: 9_000, max_uses: 2, require_human_confirmation: true },
        delegation: Delegation { allowed: true, max_depth: 1 }, revocation: parent.revocation.clone(),
        issuer_pub: String::new(), subject_pub: b64(worker.verifying_key().as_bytes()), sig: String::new(),
    };
    sign_authority(&mut child, &agent);
    (parent, child, root, agent)
}

#[test] fn strictly_narrower_delegation_is_valid() { let (p, c, _, _) = delegation_pair(); assert!(check_attenuation(&c, &p).ok); }

#[test]
fn every_important_delegation_widening_is_rejected() {
    let mutations: Vec<fn(&mut AuthorityObject)> = vec![
        |c| c.resource = "vault/*".into(),
        |c| c.constraints.not_before = 500,
        |c| c.constraints.expires = 20_000,
        |c| c.constraints.max_uses = 20,
        |c| c.constraints.require_human_confirmation = false,
        |c| c.delegation.max_depth = 2,
        |c| c.revocation.id = "attacker-controlled".into(),
        |c| c.revocation.freshness_required_sec = 60,
    ];
    for mutate in mutations {
        let (parent, mut child, _, agent) = delegation_pair(); mutate(&mut child); sign_authority(&mut child, &agent);
        assert!(!check_attenuation(&child, &parent).ok);
    }
}

#[test]
fn delegation_must_be_signed_by_parent_subject() {
    let (parent, mut child, root, _) = delegation_pair(); sign_authority(&mut child, &root);
    assert!(!check_attenuation(&child, &parent).ok);
}

#[test]
fn malformed_json_denies_without_panicking() {
    let verdict = evaluate_json("{not-json");
    assert!(!verdict.allow); assert!(verdict.json.contains("MALFORMED_REQUEST"));
}

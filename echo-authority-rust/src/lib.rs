//! Hardened Echo Authority Protocol reference implementation.
//!
//! Version 0.2 binds identities to trusted keys, binds invocations to a content-derived
//! authority id, uses unambiguous signed encodings and integer money, consumes verifier
//! state in one transition, and supports gateway-signed receipts.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Ok,
    UntrustedIssuer,
    BadAuthoritySignature,
    SubjectKeyMismatch,
    BadInvocationSignature,
    AuthorityIdMismatch,
    SubjectMismatch,
    CapabilityMismatch,
    ResourceMismatch,
    InvalidAmount,
    ValueLimitExceeded,
    TotalLimitExceeded,
    CurrencyMismatch,
    InvalidConstraints,
    Expired,
    NotYetValid,
    InvocationTimeInvalid,
    MaxUsesExceeded,
    AudienceMismatch,
    NonceReplay,
    Revoked,
    RevocationStale,
    OfflineValueExceeded,
    ForbiddenCapability,
    HumanConfirmationRequired,
    DelegationNotSubset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub currency: Option<String>,
    #[serde(default)]
    pub max_per_action_minor: u64,
    #[serde(default)]
    pub max_total_minor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    pub not_before: i64,
    pub expires: i64,
    pub max_uses: u64,
    #[serde(default)]
    pub require_human_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub max_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub method: String,
    pub id: String,
    pub freshness_required_sec: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityObject {
    pub issuer: String,
    pub subject: String,
    pub capability: String,
    pub resource: String,
    pub scope: Scope,
    pub constraints: Constraints,
    pub delegation: Delegation,
    pub revocation: Revocation,
    /// Must equal the verifier-controlled key registered for `issuer`.
    pub issuer_pub: String,
    /// The only key permitted to exercise this grant.
    pub subject_pub: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub authority_id: String,
    pub invocation_id: String,
    pub subject: String,
    pub capability: String,
    pub resource: String,
    #[serde(default)]
    pub amount_minor: u64,
    pub currency: Option<String>,
    pub audience: String,
    pub nonce: String,
    pub created: i64,
    #[serde(default)]
    pub human_confirmed: bool,
    pub subject_pub: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptClaims {
    pub authority_id: String,
    pub invocation_id: String,
    pub subject: String,
    pub capability: String,
    pub resource: String,
    pub amount_minor: u64,
    pub currency: Option<String>,
    pub audience: String,
    pub nonce: String,
    pub authorized_at: i64,
    pub previous_receipt_head: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub claims: ReceiptClaims,
    pub gateway_id: String,
    pub gateway_pub: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorderResult {
    pub decision: Decision,
    pub reason: Reason,
    pub receipt: Option<ReceiptClaims>,
}

impl BorderResult {
    fn deny(reason: Reason) -> Self {
        Self {
            decision: Decision::Deny,
            reason,
            receipt: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerifierState {
    pub now: i64,
    pub audience: String,
    pub online: bool,
    pub revocation_age_sec: i64,
    pub revoked_ids: BTreeSet<String>,
    pub used_nonces: BTreeSet<String>,
    pub uses: BTreeMap<String, u64>,
    pub spent_total_minor: BTreeMap<String, u64>,
    pub offline_limit_minor: u64,
    pub max_clock_skew_sec: i64,
    pub max_invocation_age_sec: i64,
    pub trusted_issuers: BTreeMap<String, String>,
    pub previous_receipt_head: Option<String>,
}

pub const FORBIDDEN_CAPS: &[&str] = &[
    "root.export",
    "recovery.export",
    "audit.disable",
    "authority.exceed-owner",
    "history.rewrite",
];

/// Length-prefixing makes separators inside user-controlled strings unambiguous.
fn encode_fields(domain: &str, fields: &[String]) -> String {
    let mut out = format!("{domain}\nv0.2\n");
    for field in fields {
        out.push_str(&field.len().to_string());
        out.push(':');
        out.push_str(field);
        out.push('\n');
    }
    out
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

pub fn canonical_authority(a: &AuthorityObject) -> String {
    encode_fields(
        "ECHO-AUTHORITY",
        &[
            a.issuer.clone(),
            a.subject.clone(),
            a.capability.clone(),
            a.resource.clone(),
            opt(&a.scope.currency),
            a.scope.max_per_action_minor.to_string(),
            a.scope.max_total_minor.to_string(),
            a.constraints.not_before.to_string(),
            a.constraints.expires.to_string(),
            a.constraints.max_uses.to_string(),
            a.constraints.require_human_confirmation.to_string(),
            a.delegation.allowed.to_string(),
            a.delegation.max_depth.to_string(),
            a.revocation.method.clone(),
            a.revocation.id.clone(),
            a.revocation.freshness_required_sec.to_string(),
            a.issuer_pub.clone(),
            a.subject_pub.clone(),
        ],
    )
}

pub fn canonical_invocation(i: &Invocation) -> String {
    encode_fields(
        "ECHO-INVOCATION",
        &[
            i.authority_id.clone(),
            i.invocation_id.clone(),
            i.subject.clone(),
            i.capability.clone(),
            i.resource.clone(),
            i.amount_minor.to_string(),
            opt(&i.currency),
            i.audience.clone(),
            i.nonce.clone(),
            i.created.to_string(),
            i.human_confirmed.to_string(),
            i.subject_pub.clone(),
        ],
    )
}

pub fn canonical_receipt(r: &ReceiptClaims, gateway_id: &str, gateway_pub: &str) -> String {
    encode_fields(
        "ECHO-RECEIPT",
        &[
            r.authority_id.clone(),
            r.invocation_id.clone(),
            r.subject.clone(),
            r.capability.clone(),
            r.resource.clone(),
            r.amount_minor.to_string(),
            opt(&r.currency),
            r.audience.clone(),
            r.nonce.clone(),
            r.authorized_at.to_string(),
            opt(&r.previous_receipt_head),
            gateway_id.to_string(),
            gateway_pub.to_string(),
        ],
    )
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn authority_id(a: &AuthorityObject) -> String {
    sha256_hex(&encode_fields(
        "ECHO-AUTHORITY-ID",
        &[canonical_authority(a), a.sig.clone()],
    ))
}

pub fn receipt_head(r: &ReceiptClaims) -> String {
    sha256_hex(&encode_fields(
        "ECHO-RECEIPT-HEAD",
        &[canonical_receipt(r, "", "")],
    ))
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            continue;
        }
        let val = lookup[c as usize];
        if val == 255 {
            return None;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

pub fn verify_sig(msg: &str, pub_b64: &str, sig_b64: &str) -> bool {
    let public = match base64_decode(pub_b64) {
        Some(v) if v.len() == 32 => v,
        _ => return false,
    };
    let signature = match base64_decode(sig_b64) {
        Some(v) if v.len() == 64 => v,
        _ => return false,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature);
    vk.verify(msg.as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

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
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn sign_receipt(claims: ReceiptClaims, gateway_id: &str, key: &SigningKey) -> SignedReceipt {
    let gateway_pub = b64(key.verifying_key().as_bytes());
    let message = canonical_receipt(&claims, gateway_id, &gateway_pub);
    SignedReceipt {
        claims,
        gateway_id: gateway_id.to_string(),
        gateway_pub,
        sig: b64(&key.sign(message.as_bytes()).to_bytes()),
    }
}

pub fn verify_signed_receipt(
    receipt: &SignedReceipt,
    trusted_gateways: &BTreeMap<String, String>,
) -> bool {
    if trusted_gateways.get(&receipt.gateway_id) != Some(&receipt.gateway_pub) {
        return false;
    }
    verify_sig(
        &canonical_receipt(&receipt.claims, &receipt.gateway_id, &receipt.gateway_pub),
        &receipt.gateway_pub,
        &receipt.sig,
    )
}

pub fn resource_within(child: &str, parent: &str) -> bool {
    if child.contains("..")
        || parent.contains("..")
        || child.contains('\0')
        || parent.contains('\0')
    {
        return false;
    }
    if child == parent {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix("/*") {
        return child
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'));
    }
    child
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn valid_authority_shape(a: &AuthorityObject) -> bool {
    !a.issuer.is_empty()
        && !a.subject.is_empty()
        && !a.capability.is_empty()
        && !a.resource.is_empty()
        && !a.issuer_pub.is_empty()
        && !a.subject_pub.is_empty()
        && a.constraints.not_before < a.constraints.expires
        && a.constraints.max_uses > 0
        && a.revocation.freshness_required_sec >= 0
        && !a.revocation.method.is_empty()
        && !a.revocation.id.is_empty()
        && (a.scope.max_total_minor == 0 || a.scope.max_per_action_minor <= a.scope.max_total_minor)
}

pub fn border_check(a: &AuthorityObject, i: &Invocation, state: &VerifierState) -> BorderResult {
    if !valid_authority_shape(a) {
        return BorderResult::deny(Reason::InvalidConstraints);
    }
    if FORBIDDEN_CAPS.contains(&a.capability.as_str()) {
        return BorderResult::deny(Reason::ForbiddenCapability);
    }
    if state.trusted_issuers.get(&a.issuer) != Some(&a.issuer_pub) {
        return BorderResult::deny(Reason::UntrustedIssuer);
    }
    if !verify_sig(&canonical_authority(a), &a.issuer_pub, &a.sig) {
        return BorderResult::deny(Reason::BadAuthoritySignature);
    }
    if i.subject_pub != a.subject_pub {
        return BorderResult::deny(Reason::SubjectKeyMismatch);
    }
    if !verify_sig(&canonical_invocation(i), &i.subject_pub, &i.sig) {
        return BorderResult::deny(Reason::BadInvocationSignature);
    }
    if i.authority_id != authority_id(a) {
        return BorderResult::deny(Reason::AuthorityIdMismatch);
    }
    if i.subject != a.subject {
        return BorderResult::deny(Reason::SubjectMismatch);
    }
    if i.capability != a.capability {
        return BorderResult::deny(Reason::CapabilityMismatch);
    }
    if !resource_within(&i.resource, &a.resource) {
        return BorderResult::deny(Reason::ResourceMismatch);
    }
    if i.amount_minor > 0 {
        if i.currency.as_deref().unwrap_or("").is_empty() || a.scope.currency != i.currency {
            return BorderResult::deny(Reason::CurrencyMismatch);
        }
        if i.amount_minor > a.scope.max_per_action_minor {
            return BorderResult::deny(Reason::ValueLimitExceeded);
        }
        let already = *state.spent_total_minor.get(&i.authority_id).unwrap_or(&0);
        if already
            .checked_add(i.amount_minor)
            .map_or(true, |total| total > a.scope.max_total_minor)
        {
            return BorderResult::deny(Reason::TotalLimitExceeded);
        }
    } else if i.currency.is_some() {
        return BorderResult::deny(Reason::InvalidAmount);
    }
    if state.now < a.constraints.not_before {
        return BorderResult::deny(Reason::NotYetValid);
    }
    if state.now >= a.constraints.expires {
        return BorderResult::deny(Reason::Expired);
    }
    if i.created < a.constraints.not_before
        || i.created >= a.constraints.expires
        || i.created > state.now.saturating_add(state.max_clock_skew_sec)
        || state.now.saturating_sub(i.created) > state.max_invocation_age_sec
    {
        return BorderResult::deny(Reason::InvocationTimeInvalid);
    }
    if *state.uses.get(&i.authority_id).unwrap_or(&0) >= a.constraints.max_uses {
        return BorderResult::deny(Reason::MaxUsesExceeded);
    }
    if i.audience != state.audience {
        return BorderResult::deny(Reason::AudienceMismatch);
    }
    if i.nonce.is_empty() || state.used_nonces.contains(&i.nonce) {
        return BorderResult::deny(Reason::NonceReplay);
    }
    if state.revoked_ids.contains(&a.revocation.id) {
        return BorderResult::deny(Reason::Revoked);
    }
    if !state.online {
        if state.revocation_age_sec < 0
            || state.revocation_age_sec > a.revocation.freshness_required_sec
        {
            return BorderResult::deny(Reason::RevocationStale);
        }
        if i.amount_minor > state.offline_limit_minor {
            return BorderResult::deny(Reason::OfflineValueExceeded);
        }
    }
    if a.constraints.require_human_confirmation && !i.human_confirmed {
        return BorderResult::deny(Reason::HumanConfirmationRequired);
    }
    let receipt = ReceiptClaims {
        authority_id: i.authority_id.clone(),
        invocation_id: i.invocation_id.clone(),
        subject: i.subject.clone(),
        capability: i.capability.clone(),
        resource: i.resource.clone(),
        amount_minor: i.amount_minor,
        currency: i.currency.clone(),
        audience: i.audience.clone(),
        nonce: i.nonce.clone(),
        authorized_at: state.now,
        previous_receipt_head: state.previous_receipt_head.clone(),
    };
    BorderResult {
        decision: Decision::Allow,
        reason: Reason::Ok,
        receipt: Some(receipt),
    }
}

/// Produces one state transition. Shared deployments must execute this transition inside one
/// database transaction or lock so two callers cannot observe the same pre-consumption state.
pub fn authorize_and_record(
    a: &AuthorityObject,
    i: &Invocation,
    state: &mut VerifierState,
) -> BorderResult {
    let result = border_check(a, i, state);
    if result.decision == Decision::Allow {
        state.used_nonces.insert(i.nonce.clone());
        *state.uses.entry(i.authority_id.clone()).or_default() += 1;
        let spent = state
            .spent_total_minor
            .entry(i.authority_id.clone())
            .or_default();
        *spent = spent.saturating_add(i.amount_minor);
        if let Some(receipt) = &result.receipt {
            state.previous_receipt_head = Some(receipt_head(receipt));
        }
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttenuationResult {
    pub ok: bool,
    pub violations: Vec<String>,
}

pub fn check_attenuation(child: &AuthorityObject, parent: &AuthorityObject) -> AttenuationResult {
    let mut v = Vec::new();
    if !verify_sig(
        &canonical_authority(parent),
        &parent.issuer_pub,
        &parent.sig,
    ) {
        v.push("parent signature is invalid".into());
    }
    if !verify_sig(&canonical_authority(child), &child.issuer_pub, &child.sig) {
        v.push("child signature is invalid".into());
    }
    if !parent.delegation.allowed {
        v.push("parent does not permit delegation".into());
    }
    if parent.delegation.max_depth == 0 {
        v.push("parent delegation depth is exhausted".into());
    }
    if child.issuer != parent.subject || child.issuer_pub != parent.subject_pub {
        v.push("child must be issued by the parent's bound subject key".into());
    }
    if child.capability != parent.capability {
        v.push("capability differs from parent".into());
    }
    if !resource_within(&child.resource, &parent.resource) {
        v.push("resource is not within parent".into());
    }
    if child.scope.currency != parent.scope.currency {
        v.push("currency differs from parent".into());
    }
    if child.scope.max_per_action_minor > parent.scope.max_per_action_minor {
        v.push("per-action limit exceeds parent".into());
    }
    if child.scope.max_total_minor > parent.scope.max_total_minor {
        v.push("total limit exceeds parent".into());
    }
    if child.constraints.not_before < parent.constraints.not_before {
        v.push("child starts before parent".into());
    }
    if child.constraints.expires > parent.constraints.expires {
        v.push("child expires after parent".into());
    }
    if child.constraints.max_uses > parent.constraints.max_uses {
        v.push("child use budget exceeds parent".into());
    }
    if parent.constraints.require_human_confirmation
        && !child.constraints.require_human_confirmation
    {
        v.push("child removes required human confirmation".into());
    }
    if child.delegation.max_depth >= parent.delegation.max_depth {
        v.push("delegation depth is not narrower".into());
    }
    if child.revocation.method != parent.revocation.method
        || child.revocation.id != parent.revocation.id
    {
        v.push("child must preserve parent revocation".into());
    }
    if child.revocation.freshness_required_sec > parent.revocation.freshness_required_sec {
        v.push("child permits staler revocation state".into());
    }
    AttenuationResult {
        ok: v.is_empty(),
        violations: v,
    }
}

pub fn reason_str(r: Reason) -> &'static str {
    match r {
        Reason::Ok => "OK",
        Reason::UntrustedIssuer => "UNTRUSTED_ISSUER",
        Reason::BadAuthoritySignature => "BAD_AUTHORITY_SIGNATURE",
        Reason::SubjectKeyMismatch => "SUBJECT_KEY_MISMATCH",
        Reason::BadInvocationSignature => "BAD_INVOCATION_SIGNATURE",
        Reason::AuthorityIdMismatch => "AUTHORITY_ID_MISMATCH",
        Reason::SubjectMismatch => "SUBJECT_MISMATCH",
        Reason::CapabilityMismatch => "CAPABILITY_MISMATCH",
        Reason::ResourceMismatch => "RESOURCE_MISMATCH",
        Reason::InvalidAmount => "INVALID_AMOUNT",
        Reason::ValueLimitExceeded => "VALUE_LIMIT_EXCEEDED",
        Reason::TotalLimitExceeded => "TOTAL_LIMIT_EXCEEDED",
        Reason::CurrencyMismatch => "CURRENCY_MISMATCH",
        Reason::InvalidConstraints => "INVALID_CONSTRAINTS",
        Reason::Expired => "EXPIRED",
        Reason::NotYetValid => "NOT_YET_VALID",
        Reason::InvocationTimeInvalid => "INVOCATION_TIME_INVALID",
        Reason::MaxUsesExceeded => "MAX_USES_EXCEEDED",
        Reason::AudienceMismatch => "AUDIENCE_MISMATCH",
        Reason::NonceReplay => "NONCE_REPLAY",
        Reason::Revoked => "REVOKED",
        Reason::RevocationStale => "REVOCATION_STALE",
        Reason::OfflineValueExceeded => "OFFLINE_VALUE_EXCEEDED",
        Reason::ForbiddenCapability => "FORBIDDEN_CAPABILITY",
        Reason::HumanConfirmationRequired => "HUMAN_CONFIRMATION_REQUIRED",
        Reason::DelegationNotSubset => "DELEGATION_NOT_SUBSET",
    }
}

#[derive(Deserialize)]
struct StateWire {
    now: i64,
    audience: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    revocation_age_sec: i64,
    #[serde(default)]
    revoked_ids: Vec<String>,
    #[serde(default)]
    used_nonces: Vec<String>,
    #[serde(default)]
    uses: BTreeMap<String, u64>,
    #[serde(default)]
    spent_total_minor: BTreeMap<String, u64>,
    #[serde(default)]
    offline_limit_minor: u64,
    #[serde(default = "default_clock_skew")]
    max_clock_skew_sec: i64,
    #[serde(default = "default_invocation_age")]
    max_invocation_age_sec: i64,
    #[serde(default)]
    trusted_issuers: BTreeMap<String, String>,
    #[serde(default)]
    previous_receipt_head: Option<String>,
}
fn default_clock_skew() -> i64 {
    30
}
fn default_invocation_age() -> i64 {
    300
}

#[derive(Deserialize)]
struct RequestWire {
    authority: AuthorityObject,
    invocation: Invocation,
    state: StateWire,
}

pub struct JsonVerdict {
    pub json: String,
    pub allow: bool,
}

pub fn evaluate_json(input: &str) -> JsonVerdict {
    let req: RequestWire = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(_) => {
            return JsonVerdict {
                json: "{\"decision\":\"Deny\",\"reason\":\"MALFORMED_REQUEST\",\"receipt\":null}"
                    .into(),
                allow: false,
            }
        }
    };
    let state = VerifierState {
        now: req.state.now,
        audience: req.state.audience,
        online: req.state.online,
        revocation_age_sec: req.state.revocation_age_sec,
        revoked_ids: req.state.revoked_ids.into_iter().collect(),
        used_nonces: req.state.used_nonces.into_iter().collect(),
        uses: req.state.uses,
        spent_total_minor: req.state.spent_total_minor,
        offline_limit_minor: req.state.offline_limit_minor,
        max_clock_skew_sec: req.state.max_clock_skew_sec,
        max_invocation_age_sec: req.state.max_invocation_age_sec,
        trusted_issuers: req.state.trusted_issuers,
        previous_receipt_head: req.state.previous_receipt_head,
    };
    let result = border_check(&req.authority, &req.invocation, &state);
    let allow = result.decision == Decision::Allow;
    let json = serde_json::to_string(&result).unwrap_or_else(|_| {
        "{\"decision\":\"Deny\",\"reason\":\"MALFORMED_REQUEST\",\"receipt\":null}".into()
    });
    JsonVerdict { json, allow }
}

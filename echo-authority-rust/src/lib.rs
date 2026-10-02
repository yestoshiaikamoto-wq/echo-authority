//! echo-authority-core — a reference implementation of the Echo Authority Protocol, Draft 0.1.
//!
//! This crate is a SECOND, INDEPENDENT implementation of the deterministic Border Control
//! verifier and the attenuation-only delegation rule. It exists to prove the protocol is a
//! shared language, not one company's server: given the same Authority Object, the same
//! Invocation, and the same verifier state, this Rust code MUST return the identical verdict
//! as the TypeScript reference at /protocol.
//!
//! The verifier is deliberately boring. No model, no heuristics, no network. Every decision
//! falls out of the object's own declared bounds.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Reason codes — the complete, ordered vocabulary of why Border Control decides.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Ok,
    BadAuthoritySignature,
    BadInvocationSignature,
    SubjectMismatch,
    CapabilityMismatch,
    ResourceMismatch,
    ValueLimitExceeded,
    TotalLimitExceeded,
    CurrencyMismatch,
    Expired,
    NotYetValid,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct BorderResult {
    pub decision: Decision,
    pub reason: Reason,
    /// On ALLOW, an opaque commitment over the exercised terms. Proof, never data.
    pub receipt: Option<String>,
}

impl BorderResult {
    fn deny(reason: Reason) -> Self {
        BorderResult { decision: Decision::Deny, reason, receipt: None }
    }
}

// ---------------------------------------------------------------------------
// The Authority Object and Invocation.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub currency: Option<String>,
    #[serde(default)]
    pub max_per_action: f64,
    #[serde(default)]
    pub max_total: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Unix seconds. Action is invalid before this instant.
    pub not_before: i64,
    /// Unix seconds. Action is invalid at/after this instant.
    pub expires: i64,
    pub max_uses: u64,
    /// If true, an interactive human confirmation MUST accompany the invocation.
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
    /// e.g. "revocation-list". A revoked id in verifier state ends the grant.
    pub method: String,
    pub id: String,
    /// The gateway must have checked revocation within this many seconds.
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
    /// Base64 Ed25519 public key of the issuer (for signature verification).
    pub issuer_pub: String,
    /// Base64 signature over the canonical form.
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
    pub amount: f64,
    pub currency: Option<String>,
    pub audience: String,
    pub nonce: String,
    pub created: i64,
    /// True only when a human interactively confirmed this specific invocation.
    #[serde(default)]
    pub human_confirmed: bool,
    /// Base64 Ed25519 public key of the subject.
    pub subject_pub: String,
    pub sig: String,
}

/// Mutable verifier state — what the gateway knows at decision time.
#[derive(Debug, Clone, Default)]
pub struct VerifierState {
    pub now: i64,
    pub audience: String,
    pub online: bool,
    pub revocation_age_sec: i64,
    pub revoked_ids: std::collections::BTreeSet<String>,
    pub used_nonces: std::collections::BTreeSet<String>,
    /// authority_id -> uses already consumed.
    pub uses: BTreeMap<String, u64>,
    /// authority_id -> value already spent.
    pub spent_total: BTreeMap<String, f64>,
    /// A payment above this value cannot be authorized while offline.
    pub offline_limit: f64,
}

// ---------------------------------------------------------------------------
// Never-grantable capabilities. No signature, no delegation, no human can grant these.
// ---------------------------------------------------------------------------

pub const FORBIDDEN_CAPS: &[&str] = &[
    "export-root-key",
    "export-recovery-secret",
    "disable-audit",
    "grant-beyond-owner",
    "rewrite-history",
];

// ---------------------------------------------------------------------------
// Canonical serialization + signature helpers.
//
// The canonical string is deterministic and field-ordered. Two implementations that
// agree on this string will verify each other's signatures. It commits every field
// that defines the grant's power.
// ---------------------------------------------------------------------------

pub fn canonical_authority(a: &AuthorityObject) -> String {
    format!(
        "ECHO-AUTHORITY\nv0.1\n{}\n{}\n{}\n{}\n{}|{}|{}\n{}|{}|{}|{}\n{}|{}\n{}|{}|{}",
        a.issuer,
        a.subject,
        a.capability,
        a.resource,
        a.scope.currency.clone().unwrap_or_default(),
        a.scope.max_per_action,
        a.scope.max_total,
        a.constraints.not_before,
        a.constraints.expires,
        a.constraints.max_uses,
        a.constraints.require_human_confirmation,
        a.delegation.allowed,
        a.delegation.max_depth,
        a.revocation.method,
        a.revocation.id,
        a.revocation.freshness_required_sec,
    )
}

pub fn canonical_invocation(i: &Invocation) -> String {
    format!(
        "ECHO-INVOCATION\nv0.1\n{}\n{}\n{}\n{}\n{}\n{}|{}\n{}\n{}\n{}",
        i.authority_id,
        i.invocation_id,
        i.subject,
        i.capability,
        i.resource,
        i.amount,
        i.currency.clone().unwrap_or_default(),
        i.audience,
        i.nonce,
        i.created,
    )
}

fn verify_sig(msg: &str, pub_b64: &str, sig_b64: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pub_bytes = match base64_decode(pub_b64) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match base64_decode(sig_b64) {
        Some(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pub_bytes);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut sg = [0u8; 64];
    sg.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sg);
    vk.verify(msg.as_bytes(), &sig).is_ok()
}

/// Opaque commitment written on ALLOW. Commits the exercised terms; carries no data.
fn receipt_head(a: &AuthorityObject, i: &Invocation) -> String {
    let mut h = Sha256::new();
    h.update(
        format!(
            "ECHO-RECEIPT\n{}\n{}\n{}\n{}\n{}\n{}",
            a.issuer, i.subject, i.capability, i.resource, i.amount, i.invocation_id
        )
        .as_bytes(),
    );
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Resource subset test — used by both Border Control and attenuation.
//
// A resource `child` is within `parent` when parent is an exact match, or parent is a
// glob prefix (`vault/*`) that covers child, or parent is a path prefix of child.
// ---------------------------------------------------------------------------

pub fn resource_within(child: &str, parent: &str) -> bool {
    if child == parent {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }
    if let Some(prefix) = parent.strip_suffix('/') {
        return child.starts_with(prefix);
    }
    child.starts_with(&format!("{parent}/"))
}

// ---------------------------------------------------------------------------
// Border Control — the deterministic verifier. This is the load-bearing wall.
//
// The check order is fixed and each gate returns the exact reason it failed. A conformant
// implementation in any language must produce the identical (decision, reason) pair.
// ---------------------------------------------------------------------------

pub fn border_check(
    authority: &AuthorityObject,
    invocation: &Invocation,
    state: &VerifierState,
) -> BorderResult {
    // 1. Both signatures must verify. Intelligence cannot forge authorship.
    if !verify_sig(&canonical_authority(authority), &authority.issuer_pub, &authority.sig) {
        return BorderResult::deny(Reason::BadAuthoritySignature);
    }
    if !verify_sig(&canonical_invocation(invocation), &invocation.subject_pub, &invocation.sig) {
        return BorderResult::deny(Reason::BadInvocationSignature);
    }

    // 2. The invocation must come from the subject the authority names.
    if invocation.subject != authority.subject {
        return BorderResult::deny(Reason::SubjectMismatch);
    }

    // 3. The requested capability must match the granted one.
    if invocation.capability != authority.capability {
        return BorderResult::deny(Reason::CapabilityMismatch);
    }

    // 4. The target resource must be within the granted resource.
    if !resource_within(&invocation.resource, &authority.resource) {
        return BorderResult::deny(Reason::ResourceMismatch);
    }

    // 5. Value must respect currency and both caps (per-action and running total).
    if invocation.amount > 0.0 {
        if authority.scope.currency != invocation.currency {
            return BorderResult::deny(Reason::CurrencyMismatch);
        }
        if invocation.amount > authority.scope.max_per_action {
            return BorderResult::deny(Reason::ValueLimitExceeded);
        }
        let already = *state.spent_total.get(&invocation.authority_id).unwrap_or(&0.0);
        if already + invocation.amount > authority.scope.max_total {
            return BorderResult::deny(Reason::TotalLimitExceeded);
        }
    }

    // 6. Time window.
    if state.now < authority.constraints.not_before {
        return BorderResult::deny(Reason::NotYetValid);
    }
    if state.now >= authority.constraints.expires {
        return BorderResult::deny(Reason::Expired);
    }

    // 7. Uses budget.
    let used = *state.uses.get(&invocation.authority_id).unwrap_or(&0);
    if used >= authority.constraints.max_uses {
        return BorderResult::deny(Reason::MaxUsesExceeded);
    }

    // 8. Audience binding — a grant for one gateway cannot be replayed at another.
    if invocation.audience != state.audience {
        return BorderResult::deny(Reason::AudienceMismatch);
    }

    // 9. Replay protection — a nonce is single-use.
    if state.used_nonces.contains(&invocation.nonce) {
        return BorderResult::deny(Reason::NonceReplay);
    }

    // 10. Revocation + freshness. Offline changes the risk, never the rule.
    if state.revoked_ids.contains(&authority.revocation.id) {
        return BorderResult::deny(Reason::Revoked);
    }
    if !state.online {
        if state.revocation_age_sec > authority.revocation.freshness_required_sec {
            return BorderResult::deny(Reason::RevocationStale);
        }
        if invocation.amount > state.offline_limit {
            return BorderResult::deny(Reason::OfflineValueExceeded);
        }
    }

    // 11. Never-grantable capabilities. Structural refusal — no grant can carry these.
    if FORBIDDEN_CAPS.contains(&authority.capability.as_str()) {
        return BorderResult::deny(Reason::ForbiddenCapability);
    }

    // 12. Human confirmation, when the grant demands it.
    if authority.constraints.require_human_confirmation && !invocation.human_confirmed {
        return BorderResult::deny(Reason::HumanConfirmationRequired);
    }

    BorderResult { decision: Decision::Allow, reason: Reason::Ok, receipt: Some(receipt_head(authority, invocation)) }
}

// ---------------------------------------------------------------------------
// Attenuation — a child grant may only narrow its parent. It can never widen.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AttenuationResult {
    pub ok: bool,
    pub violations: Vec<String>,
}

pub fn check_attenuation(child: &AuthorityObject, parent: &AuthorityObject) -> AttenuationResult {
    let mut v = Vec::new();

    if !parent.delegation.allowed {
        v.push("parent does not permit delegation".into());
    }
    if parent.delegation.max_depth == 0 {
        v.push("parent delegation depth is exhausted".into());
    }
    if child.capability != parent.capability {
        v.push("capability must equal the parent capability".into());
    }
    if !resource_within(&child.resource, &parent.resource) {
        v.push("resource is not within the parent resource".into());
    }
    if child.scope.max_per_action > parent.scope.max_per_action {
        v.push("scope.max_per_action exceeds parent".into());
    }
    if child.scope.max_total > parent.scope.max_total {
        v.push("scope.max_total exceeds parent".into());
    }
    if child.scope.currency != parent.scope.currency {
        v.push("scope.currency differs from parent".into());
    }
    if child.constraints.expires > parent.constraints.expires {
        v.push("child expiry is later than parent".into());
    }
    if child.constraints.max_uses > parent.constraints.max_uses {
        v.push("child max_uses exceeds parent".into());
    }
    if child.delegation.max_depth >= parent.delegation.max_depth {
        v.push("child delegation depth is not strictly less than parent".into());
    }

    AttenuationResult { ok: v.is_empty(), violations: v }
}

// ---------------------------------------------------------------------------
// A tiny, dependency-free base64 decoder (standard alphabet, no padding required).
// ---------------------------------------------------------------------------

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
        if c == b'=' || c == b'\n' || c == b'\r' {
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

// ---------------------------------------------------------------------------
// Shared JSON entry point.
//
// Both the `echo-border-control` CLI and the WebAssembly build call this ONE function, so
// the CLI, the browser, and any embedder run byte-for-byte the same verifier. Input is a
// request document; output is a canonical verdict document. Parsing never panics — a
// malformed request is itself a DENY.
// ---------------------------------------------------------------------------

/// The stable, human-readable name of a reason code (matches the TypeScript reference).
pub fn reason_str(r: Reason) -> &'static str {
    match r {
        Reason::Ok => "OK",
        Reason::BadAuthoritySignature => "BAD_AUTHORITY_SIGNATURE",
        Reason::BadInvocationSignature => "BAD_INVOCATION_SIGNATURE",
        Reason::SubjectMismatch => "SUBJECT_MISMATCH",
        Reason::CapabilityMismatch => "CAPABILITY_MISMATCH",
        Reason::ResourceMismatch => "RESOURCE_MISMATCH",
        Reason::ValueLimitExceeded => "VALUE_LIMIT_EXCEEDED",
        Reason::TotalLimitExceeded => "TOTAL_LIMIT_EXCEEDED",
        Reason::CurrencyMismatch => "CURRENCY_MISMATCH",
        Reason::Expired => "EXPIRED",
        Reason::NotYetValid => "NOT_YET_VALID",
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

#[derive(serde::Deserialize)]
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
    spent_total: BTreeMap<String, f64>,
    #[serde(default)]
    offline_limit: f64,
}

#[derive(serde::Deserialize)]
struct RequestWire {
    authority: AuthorityObject,
    invocation: Invocation,
    state: StateWire,
}

/// The outcome of evaluating a request: the canonical verdict JSON plus whether it allowed.
pub struct JsonVerdict {
    pub json: String,
    pub allow: bool,
}

/// Evaluate a `{ authority, invocation, state }` request document and return the canonical
/// verdict `{ "decision", "reason", "receipt" }`. Deterministic; never panics.
pub fn evaluate_json(input: &str) -> JsonVerdict {
    let req: RequestWire = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(_) => {
            return JsonVerdict {
                json: "{\"decision\":\"DENY\",\"reason\":\"MALFORMED_REQUEST\",\"receipt\":null}"
                    .to_string(),
                allow: false,
            };
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
        spent_total: req.state.spent_total,
        offline_limit: req.state.offline_limit,
    };

    let result = border_check(&req.authority, &req.invocation, &state);
    let allow = result.decision == Decision::Allow;
    let decision = if allow { "ALLOW" } else { "DENY" };
    let receipt = match &result.receipt {
        Some(h) => format!("\"{h}\""),
        None => "null".to_string(),
    };
    let json = format!(
        "{{\"decision\":\"{}\",\"reason\":\"{}\",\"receipt\":{}}}",
        decision,
        reason_str(result.reason),
        receipt
    );
    JsonVerdict { json, allow }
}

# Migrating from Draft 0.1 to 0.2

Version 0.2 is deliberately wire-incompatible. Draft 0.1 objects must not be silently upgraded
or accepted by the hardened verifier.

| Draft 0.1 | Version 0.2 |
|---|---|
| Issuer public key supplied and trusted by the object | `issuer_pub` must match `state.trusted_issuers[issuer]` |
| Subject key supplied only by the invocation | `subject_pub` is signed into the Authority Object and must match the invocation |
| Caller-selected `authority_id` | `authority_id(authority)` derives the only valid identifier |
| Delimiter-joined signing strings | Length-prefixed `v0.2` canonical fields |
| Floating-point amounts | `amount_minor`, `max_per_action_minor`, and `max_total_minor` as `u64` |
| Receipt hash | Canonical receipt claims plus gateway signature |
| Time-derived CLI key | Operating-system cryptographic randomness |
| Hyphenated forbidden names | Protocol names: `root.export`, `recovery.export`, `audit.disable`, `authority.exceed-owner`, `history.rewrite` |

Migration steps:

1. Generate new issuer, subject, and gateway keys through an approved secure key lifecycle.
2. Populate trusted issuer and gateway registries outside request data.
3. Reissue every standing grant using the 0.2 schema and canonical encoding.
4. Convert money to integer minor units with an explicit ISO currency.
5. Update invocation creation to calculate the content-derived authority id.
6. Place authorization and state consumption in one transaction.
7. Sign successful receipt claims with the enforcing gateway key.
8. Reject Draft 0.1 input after a short, explicitly dated migration window.

Never convert an old signature to the new format. A trusted issuer must sign a new grant.

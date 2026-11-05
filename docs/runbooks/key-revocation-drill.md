# Key-revocation drill (DIST-005A)

A revocation is an entry `{effectiveAt, keyId, reasonDigest}` in a new trust bundle whose `sequence` is higher
than the one it replaces. A revoked key is refused at or after `effectiveAt`, whatever its `ACTIVE` or
`RETIRING` state.

## What the campaign drills

| Case | Situation | Refusal |
|---|---|---|
| `sign-revoked-release-key` | The release key is revoked in the trust set the approval names. | `TRUST_KEY_REVOKED` |
| `sign-revoked-approval-key` | The approval key is revoked. | `TRUST_KEY_REVOKED` |
| `sign-revocation-stripped` | The approval was issued under a trust set that revokes the release key; an attacker strips the revocation and recomputes the trust digest. | `RELEASE_APPROVAL_TRUST_MISMATCH` |
| `export-release-trust-revoked` | A released bundle's own trust set is replaced by one that revokes its signing key, effective at the release's `verificationTime`. | `TRUST_KEY_REVOKED` |
| `import-resealed-trust-revoked` | The same replacement on the transfer medium, with resealed checksums, effective at the release's `verificationTime`. | `TRUST_KEY_REVOKED` |

Trust-sequence rollback is covered by `make rotation-test` only for `load_trust` called with an explicit
`minimum_sequence`; no product caller passes one today (see the limit below). Validity windows and role widening are
also covered by `make rotation-test`.

## Drill procedure

1. Issue the new trust bundle offline with the revocation and `sequence` + 1; record its digest.
2. Re-issue the release approval under the new trust digest; when signing under the new trust set, an approval bound
   to the old trust set is refused.
3. Run `make supply-chain-security` and `make rotation-test`; both must pass.
4. Revoke faulty candidates and releases; restore the prior signed bundle and trust set (the packet's rollback).

## What the drill proves, and its limit

The drill proves the refusal for every candidate signed, at or after `effectiveAt`, with a trust set that carries
the revocation (the approval must name that trust set), and for a release whose embedded trust set is replaced by
one that revokes its signing key at or before the release's `verificationTime` (`TRUST_KEY_REVOKED`). Building
involves no trust check.

Finding F-005A-1, carried to a successor packet, covers what is **not** refused inside this repository:

- `verify_signed_release` verifies a release against the trust set embedded in it, at the release's own
  `verificationTime`, so export and import of a release signed **before** a revocation are accepted.
- `sign_candidate` takes its trust set only from the caller and enforces no minimum trust sequence, so signing after
  `effectiveAt` with the pre-revocation trust set and an approval issued under it is accepted too.

Revocation reach belongs at import time, checked against the tenant's current trust set. Each release already binds
the trust set it was signed under: `signed-release.json` records `trustBundleFileDigest` (the digest of the embedded
`trust-bundle.json`), the signed `release-manifest.json` records `trustBundleDigest`, and the embedded trust set's
`sequence` is covered by both, so an import-time check can refuse a release signed under a superseded sequence.

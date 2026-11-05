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
| `export-release-trust-revoked` | A released bundle's own trust set is replaced by one that revokes its signing key. | `TRUST_KEY_REVOKED` |
| `import-resealed-trust-revoked` | The same replacement on the transfer medium, with resealed checksums. | `TRUST_KEY_REVOKED` |

Trust-sequence rollback, validity windows and role widening are covered by `make rotation-test`.

## Drill procedure

1. Issue the new trust bundle offline with the revocation and `sequence` + 1; record its digest.
2. Re-issue the release approval under the new trust digest; an approval bound to the old trust set is refused.
3. Run `make supply-chain-security` and `make rotation-test`; both must pass.
4. Revoke faulty candidates and releases; restore the prior signed bundle and trust set (the packet's rollback).

## Recorded limit

`verify_signed_release` verifies a release against the trust set embedded in it, at the release's own
`verificationTime`. A revocation issued after release therefore does not reach an already released bundle
inside this repository; consumers must refuse it with the newer trust set they hold. The drill above proves the
refusal for every artifact built, signed, exported or imported after the revocation.

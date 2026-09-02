# Offline release ceremony

`DIST-003` separates release approval from bundle signing. A role-scoped
`RELEASE_APPROVAL` key signs a canonical approval that binds the exact unsigned
bundle lock, SCANNED supply-chain evidence, organization, profile, validity
window, trust bundle, and permitted `BUNDLE_RELEASE` keys. The selected release
key then signs every component attestation and the root release manifest.

The implementation invokes the exact root-installed Cosign 3.1.1 binary by
absolute path and digest. It disables network signing configuration and public
transparency-log upload. Verification is explicitly local-key/offline; therefore
it does not claim public-log inclusion. Public trust keys and Cosign bundles may
enter a release, but private keys remain in the external offline ceremony.

Successful signing creates a private sibling, immediately verifies the complete
signature chain, writes a self-digested `SIGNED` record, and performs one
no-overwrite atomic rename. Promotion re-verifies after copying, emits a
self-digested `RELEASED` record, and atomically publishes under the immutable
release digest. Neither state is deployment, runtime, assurance, or tenant
acceptance evidence.

# Physical air-gap transfer

`DIST-AIR-001` exports one already immutable `RELEASED` directory and an exact
evidence-source map into a deterministic uncompressed POSIX ustar archive. The
archive contains the OCI layout, lock, signed release chain, public trust,
component SPDX documents, license and vulnerability policies, pinned advisory
snapshot, dispositions, and model custody manifest. Private material is denied.

The SHA-256 returned by export travels through a separate custody channel.
Import verifies that digest before parsing and then applies fixed entry, byte,
file, path, depth, type, metadata, and expansion bounds. It never calls generic
archive extraction: every regular file is read, checked against the canonical
transfer manifest, and created exclusively below a private destination. Full
release signatures, trust/revocation, supply-chain evidence, SPDX coverage,
model custody, and OCI closure are revalidated before atomic publication as
`VERIFIED_IMPORT`.

Relocation copies only verified OCI bytes to a local digest-addressed target,
revalidates both trees, and emits a receipt proving the source and destination
OCI tree digests are identical. It does not log into, pull from, or push to a
registry and does not assert deployment, runtime, assurance, or tenant
acceptance.

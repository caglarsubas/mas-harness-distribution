# Supply-chain evidence

`DIST-002` admits deterministic supply-chain evidence for an existing
`BUILT_UNSIGNED` bundle. It does not sign, promote, install, deploy, or execute
that bundle.

The component inventory must enumerate exactly the selected OCI components and
bind the canonical bundle-lock digest. The packet generates one reproducible
SPDX 2.3 JSON document per component, evaluates the repository's narrowed
license-policy projection, evaluates a self-digested local vulnerability
snapshot, applies only exact unexpired dispositions, and verifies the selected
model set against a separate custody manifest. Successful admission emits a
canonical `SCANNED` evidence record whose own digest covers every field except
the digest field itself. Evidence publication is create-exclusive.

Phase 0 has no preinstalled Syft or Grype binary or production advisory
database in its immutable toolchain. The implementation is therefore a
dependency-free reference SPDX generator and normalized offline advisory
evaluator. It proves the closed data contract, completeness rules, disposition
binding, model-custody boundary, deterministic evidence, and failure semantics;
it does not claim production-scanner equivalence. A later adapter may invoke an
independently pinned and preinstalled open-source scanner against a
custody-controlled local database while preserving these verdict semantics.

The fixture database is synthetic, intentionally contains one LOW and one HIGH
record, and is never presented as current security intelligence. Its fixed
assessment date makes tests reproducible. The HIGH record remains visible after
its exact `ACCEPTED_RISK` disposition is admitted. Removing the disposition,
changing its component/package/finding binding, expiring it, changing the
database digest, or moving the assessment beyond the validity window fails
closed.

Run only through the signed root-owned offline launcher with the hash-pinned
task packet. It executes `make prefetch` first, then the four DIST-002 targets,
then the cumulative `make zero-bill` gate in one OS-isolated deny-all-outbound
process tree. No source locator is opened, and no credential, registry, cloud
service, network package source, signing key, or warm-source checkout is used.

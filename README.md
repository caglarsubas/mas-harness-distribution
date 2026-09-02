# Planeon Harness Distribution

Deterministic, offline-first distribution tooling for the Planeon multi-agent harness platform. The repository begins with a bounded local OCI image-layout verifier and grows packet-by-packet into exact bundle closure, supply-chain evidence, offline signing, air-gap transfer, and modular Helm profiles.

## DIST-001 surface

The bootstrap is deliberately small:

- CPython 3.12.14 standard library only; no runtime dependency download.
- `harness-bundlectl verify <local-layout>` validates a bounded local OCI layout and emits canonical content-free evidence.
- `make prefetch` validates already provisioned root-owned tools and source locks; it does not fetch.
- `make fixture-verify` runs closure, parser, CLI, dispatcher, PORTING, and billing-boundary vectors.
- `make zero-bill` rejects hosted runners, paid/API-key dependencies, cloud provisioning, remote telemetry, runtime downloads, and mutable images.

Acceptance must run through `/opt/planeon/bin/harness-offline-launch` with the hash-pinned public packet from [Harness Onion](https://github.com/caglarsubas/harness-onion). Source, CI, merge, artifact, deployment, runtime, assurance, and tenant acceptance remain separate evidence states.

## Local development

```text
PYTHONPATH=src python3 cmd/harness-bundlectl/verify.py fixtures/oci-layout
PYTHONPATH=src python3 -m unittest discover -s tests/bootstrap -p 'test_*.py'
```

These development commands do not replace signed packet acceptance.

# Contributing

Every product change requires one hash-pinned Harness Onion task packet, one `codex/<packet-id>-<slug>` branch, and one pull request. Modify only the packet's `allowedPaths` and preserve all predecessor locks.

Warm-start repositories are reference-only and unavailable during implementation. Do not introduce hosted runners, cloud provisioning, paid or API-key services, runtime downloads, remote telemetry, mutable artifacts, or shell command transport.

Before requesting review, run the packet through the trusted offline launcher and record source, pull-request CI, merge, and exact-main CI independently.

# Modular Helm profiles

The `harness-platform` chart is a thin parent over five pre-vendored local
subcharts. A profile enables only the declared module conditions; a disabled
subchart emits no Kubernetes resource or image reference. All images are local
digest references and Helm dependency updates are forbidden during rendering.

The six profiles are `minimal-arm64`, `minimal-amd64`,
`regulated-openshift`, `bridge`, `silo`, and `air-gap`. The five non-bridge
families preserve the corresponding white-goods deployment facts. `bridge` is
a generic platform family and is not presented as an industry recommendation.

Every render is namespace-scoped, default-deny, least-privilege, resource
bounded, non-root, read-only-root-filesystem, capability-dropping, and uses a
dedicated non-automounted ServiceAccount. OpenShift output deliberately sets no
fixed UID or group and creates no SCC. Render evidence proves only deterministic
composition and static security posture—not installation, deployment health,
runtime behavior, regulatory compliance, assurance, or tenant acceptance.

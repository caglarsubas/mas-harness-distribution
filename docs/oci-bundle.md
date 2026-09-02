# Deterministic local OCI bundle staging

`DIST-OCI-001` resolves a canonical profile only against an already present, verified OCI image layout. Every selected image and chart component is SHA-256 addressed and platform-bound. Unselected modules cannot contribute components or blobs.

The builder creates a private sibling candidate, reconstructs the selected OCI index and recursive blob closure, writes a canonical `bundle.lock.json`, verifies the candidate, fsyncs it, and publishes only through a no-overwrite atomic rename. The lock has state `BUILT_UNSIGNED`; it is neither a signature nor a release, deployment, runtime, assurance, or tenant-acceptance claim.

Remote URLs, mutable tags, dependency repositories, source/destination overlap, symlinks, special files, conflicting digest meanings, missing platform coverage, existing destinations, and partial publication fail closed. Helm execution and semantic rendering belong to `DIST-004`.

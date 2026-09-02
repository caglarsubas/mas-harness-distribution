# Release trust rotation and revocation

The public trust bundle uses a monotonically increasing sequence and exact
public-key digests. Every key has explicit roles, state, and inclusive/exclusive
validity bounds. Rotation introduces a new `ACTIVE` key while the old key is
`RETIRING`; both are accepted only in their explicit overlap and only for their
declared roles.

Revocation is append-only in operational custody. A revocation effective at the
verification instant overrides `ACTIVE`, `RETIRING`, and overlap state. A trust
sequence must never be rolled back. Phase-0 tests use an explicit verification
instant rather than the wall clock so expiry and revocation outcomes are
reproducible.

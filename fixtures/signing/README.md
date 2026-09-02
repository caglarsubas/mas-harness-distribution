# Signing fixtures

The signing suite creates independent approval and release Ed25519 keypairs in
private temporary directories, signs local fixture payloads, and deletes the
directories after each test. No private key, password, seed, certificate, KMS
locator, OIDC identity, or live signature is committed here.

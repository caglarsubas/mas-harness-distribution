# Supply-chain security campaign (DIST-005A)

The campaign certifies that every production operation refuses hostile input and leaves nothing behind.
It runs offline against fixtures regenerated from this repository; it reads no cached or mutable input.

## Run it

| Target | What it runs | What it proves |
|---|---|---|
| `make build-reproducible` | `tests/reproducibility/` | Two clean builds in fresh interpreters, from byte-identical inputs with different file modes, mtimes, umask, hash seed, time zone and working directory, give the same bundle id, lock and file tree; a changed input changes the id; a corrupted source blob is refused. |
| `make supply-chain-security` | `tests/security/` | Every case in `fixtures/attacks/campaign.json` is refused with its exact code; publication races never overwrite a concurrent writer. |
| `make airgap-runtime` | `tests/airgap/test_runtime.py` | Shipped code imports no network module; Cosign runs only with offline flags and a closed environment; an imported release holds no remote or mutable reference; inside the OS-enforced offline session an outbound connection is denied. |

The report alone, outside the acceptance session:

```text
PYTHONPATH=src python3 -B scripts/run_supply_chain_campaign.py
```

It prints the canonical JSON report and exits 0 only when every case is `REFUSED_AS_EXPECTED`.

## Case layers

- `layout`: corrupt, truncated, missing, extra and symlinked blobs in an OCI layout.
- `staging`: a corrupted build source, and an extra or swapped blob injected into the build's private staging.
- `candidate`: a built candidate whose layout was corrupted, extended or consistently rewritten before signing.
- `promotion`: the same tampering between signing and promotion.
- `export`: a released bundle whose layout was rewritten before export.
- `transfer`: an archive tampered on the transfer medium, with and without resealed manifest checksums and a
  matching out-of-band digest.
- `archive`: entry-count, total-size (over 12 MiB) and gzip bombs, and over-deep or over-long member paths. The
  importer reads up to 16 MiB per archive and 4 MiB per member; `make airgap-runtime` imports a real release over
  4 MiB.
- `revocation`: see `key-revocation-drill.md`.

## When a case is UNEXPECTED

1. Stop the release; do not sign, promote or export anything built since the last passing run.
2. Read the case's `observedError` and `observedCode`. `ACCEPTED` means the hostile input was not refused: treat
   it as a security defect, not a test fix.
3. A non-empty `leftBehind` means an operation published something while refusing; remove that output by hand
   only after recording it.
4. Change the catalog's expected code only when the new refusal is at least as early and as specific, and say why
   in the pull request.

## Recorded limits

- Publication claims the destination with an exclusive `mkdir` and then atomically replaces the empty claim. A
  crash between the two leaves an empty directory that blocks that name with `*_DESTINATION_EXISTS`; inspect it
  and remove it by hand.

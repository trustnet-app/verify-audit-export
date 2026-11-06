# verify-audit-export

Offline verifier for **TrustNet audit export bundles** (spec §10.1).

A TrustNet audit export is a self-contained `tar.gz` that proves the integrity
of a tenant's (RP's) audit trail without trusting — or even contacting — the
TrustNet service. `trustnet-verify` answers the canonical auditor question:

> *Is this audit trail intact and provable?*

It reads the archive, verifies every signature and digest, recomputes the
Merkle root from the raw events, and checks the required verifier obligations.
The answer is a single exit code: `0` means the bundle is valid, `1` means it
is not.

This repository is intentionally separate from the TrustNet service codebase.
An auditor, regulator, or relying party must be able to build and inspect the
verifier in isolation: the verifier trusts the cryptography inside the bundle,
never the software that produced it.

---

## Why this exists

TrustNet's audit trail is the evidence that consent was recorded, scoped, and
respected. If verifying that evidence required running TrustNet's own
production stack, the evidence would not be independently checkable. The
export format is therefore designed so that all proof material travels *with*
the data:

- the events themselves (canonical JSON envelopes),
- a signed tree head (STH) over an RFC 6962 Merkle tree,
- the key history needed to check the signatures,
- an external time anchor (RFC 3161 timestamp or, in degraded tiers, a self
  signature),
- a consistency bridge to a previous head the auditor may already hold,
- and a signed manifest that binds every file in the archive.

The verifier is the smallest piece of software that can consume those facts.
Keeping it in its own repository means:

1. **Independence.** The verifier does not import the producer's code. It has
   its own copy of the wire-format types (`internal/auditspec`), so a bug in
   the service cannot silently hide itself by also being in the verifier.
2. **Auditability.** The entire verifier fits in a handful of files and a few
   hundred lines of Go, with no database, no Vault, no network access.
3. **Durability.** An export made today must remain verifiable years later,
   after the service has moved on. A small, stable verifier is easier to keep
   building than a large service.

---

## What a bundle contains

| File | Meaning |
|---|---|
| `manifest.json` | Compact EdDSA JWS. Its payload lists the SHA-256 of every other file, plus the bundle version, tree, seq range, event count, key id, and generation time. |
| `events.jsonl` | The exported events, one canonical (RFC 8785) envelope per line, in seq order. These exact bytes are the Merkle leaves. |
| `proofs/sth.json` | The signed tree head: canonical STH bytes verbatim and its Ed25519 signature. |
| `proofs/range.json` | The exported range and its recomputed RFC 6962 root. For v1 the range proof is degenerate: full range only. |
| `proofs/consistency.json` | Optional RFC 6962 consistency proof from an older head to this one (present when the caller supplied a previous head). |
| `keys.json` | The audit public-key history (`key_id`, SPKI PEM, algorithm, status, created-at). |
| `anchors/YYYY-MM-DD.json` | One external time anchor: the tree's STH inclusion in the meta-tree, plus the RFC 3161 token or self signature that binds the meta-root to time. |
| `purposes.jsonl` | RP bundles only: purpose versions referenced by the events. |
| `consent_texts.jsonl` | RP bundles only: consent wording versions referenced by the events. |
| `VERIFY.md` | Human-readable instructions embedded in the archive. |

Auth-period bundles (`trustnet-auth-export.v1`) have the same proof discipline
but are account-scoped, so they carry no `purposes.jsonl` or
`consent_texts.jsonl`.

---

## What it checks

`VerifyBundle` runs nine ordered checks. Every hard failure fails the bundle;
some conditions are reported as warnings because they degrade trust rather than
break integrity.

1. **Manifest JWS and file digests.** The compact JWS must be EdDSA, its `kid`
   must resolve in `keys.json`, and its payload must list every archived file
   with a matching SHA-256. Unlisted extra files warn.
2. **Envelope shape.** Each `events.jsonl` line must parse as a v2 envelope
   with a valid `producer`. An unknown envelope version is an error; an unknown
   event type is only a warning.
3. **Leaf hashes.** Leaves are RFC 6962 domain-separated hashes of the exact
   JSONL bytes.
4. **Range root.** The recomputed RFC 6962 root over all leaves must equal the
   root in `proofs/sth.json` and `proofs/range.json`; the range must cover
   `[0, n-1]` and the count must match `event_count`.
5. **STH signature.** The STH canonical bytes must be verbatim, the tree must
   match the manifest, and the Ed25519 signature must verify against the key
   named by `key_id`.
6. **Anchor inclusion and time binding.** The anchored STH must be included in
   the meta-root; the meta-root must be bound by an RFC 3161 token (verified
   offline against its embedded chain) or by a self signature. Self-anchored
   bundles and certificate-less tokens produce a **degraded-trust warning**.
7. **Consistency bridge.** When `proofs/consistency.json` is present, the RFC
   6962 consistency proof must connect the previous root to the current one.
8. **Purpose/consent-text resolution** (RP bundles). Every referenced purpose
   and consent wording must resolve, and `SHA-256(body)` must equal the
   claimed `text_hash` and the hash anchored by the corresponding
   `purpose.registered`/`purpose.updated` event.
9. **Verifier obligations** (RP bundles, spec §10.1). Reference integrity
   (`supersedes`, `revokes`, `suspension_ref` point at earlier compatible
   events), the suspension invariant, leaf 0 is `rp.registered`, at most one
   `rp.deleted`, and only `export.generated` may follow `rp.deleted`.

### What it does *not* prove

- It does **not** prove that the events are a complete history of the RP's
  activities outside the exported range. The bundle proves the trail it
  contains, and (with a consistency bridge) that it extends a head you already
  hold.
- A **self-anchored** bundle is integrity-checked but its *time* is only
  TrustNet's claim; treat that warning as a deployment-tier signal, not a
  clean bill of health.
- It does not judge whether the events describe lawful processing. It proves
  they were recorded consistently and have not been altered.

---

## Install and run

Requires Go 1.27 or newer.

```sh
go install github.com/trustnet-app/verify-audit-export/cmd/trustnet-verify@latest
```

Verify a bundle:

```sh
trustnet-verify rp-export.tar.gz
```

Add `-verbose` to print informational findings (manifest key id, verified STH
details, and so on).

```sh
trustnet-verify -verbose rp-export.tar.gz
```

Or run it straight from a checkout:

```sh
go run ./cmd/trustnet-verify -verbose bundle.tar.gz
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every hard check passed. Warnings may still be printed. |
| `1` | The bundle is invalid, unreadable, or truncated. |
| `2` | Usage error (wrong number of arguments). |

Sample output:

```
  warning degraded trust: self-anchored (dev/staging tier)
  info    manifest: kid audit-key:v7, tree rp:demo, range [0,41], events 42
  info    sth rp:demo size 43 signature ok with key audit-key:v7
  info    verified 42 events against STH 2026-08-23T00:00:00Z size 43
trustnet-verify: rp-export.tar.gz: VALID — the audit trail is intact and provable (spec §10.1)
```

---

## Development

The verifier is a single Go module. The wire-format types it needs live in
`internal/auditspec/`; everything else is the verification pipeline.

```sh
make check     # gofmt + vet + test -race
make test      # go test ./...
make build     # build ./cmd/trustnet-verify
```

### Repository layout

| Path | Purpose |
|---|---|
| `verify.go` | The nine-step verification pipeline. |
| `archive.go` | Deterministic tar.gz read/write and SHA-256 helper. |
| `jws.go` | Compact EdDSA JWS verification. |
| `manifest.go` | Bundle version constants and signing-manifest wire shape. |
| `merkle.go` | RFC 6962 Merkle tree hash over the bundle's leaves. |
| `internal/auditspec/` | Self-contained copy of the audit wire format: envelopes, STH, keys, event taxonomy, JCS canonicalization, hashes, suspension invariant. |
| `conformance_test.go` | Synthetic valid bundle plus one mutation per trust-chain link. |
| `cmd/trustnet-verify/` | CLI wrapper. |

### Keeping the spec copy in sync

`internal/auditspec` intentionally duplicates the wire format rather than
importing the TrustNet service. When the export format or the event taxonomy
changes, update this copy in the same change as the producer, and extend the
conformance corpus. Bump `BundleVersion...` when the on-disk format changes in
a way an older verifier cannot read.

---

## Security notes

- The verifier makes **no network calls** and reads only the supplied file.
- `keys.json` travels inside the bundle. Trust in those keys comes from the
  external anchor (RFC 3161 token) binding the key history to a time before
  the events were disputed; a self-anchored bundle provides no such external
  corroboration.
- Unknown event types are warnings so future taxonomy additions stay
  verifiable. Unknown envelope versions are errors: the verifier never guesses
  at a format it does not understand.
- A bundle that passes verification is internally consistent and its history
  is provable. Treat the warnings as material to the assurance decision.

---

## References

- TrustNet audit architecture: `_DOCS/02-architecture/audit.md` in the
  `trustnet_ory` repository.
- Spec §10.1 (per-RP export and verifier obligations), §9 (external
  anchoring), §5 (event taxonomy and suspension invariant).
- RFC 6962 (Certificate Transparency Merkle trees), RFC 7515/RFC 8037 (JWS
  and EdDSA), RFC 8785 (JSON Canonicalization Scheme), RFC 3161 (Time-Stamp
  Protocol).

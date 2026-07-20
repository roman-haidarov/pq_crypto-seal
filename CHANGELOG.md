# Changelog

## 0.1.1

- Release hygiene: CI Actions pinned by commit SHA, `permissions: contents: read`,
  fuzz + gem-smoke + `release_contract_check` jobs; ignore `.DS_Store` / binaries.
- Aggressive internal refactor: parsing, recipient wrapping, one-shot operations,
  streaming, atomic files, padding policies, and resource limits now live in
  focused objects instead of large branching methods. Public API and wire v1
  remain unchanged.
- Padding enforcement now validates both policy id and the canonical target;
  parameterized fixed/bucket requirements cannot masquerade as one another.
- Added exact deterministic envelope/stream equivalence, official X-Wing
  draft-10 decapsulation KATs, partial-read/write regression tests, and a
  release-contract checker.
- Release gem contains production code plus only the AEGIS-256 sources needed
  to compile; tests, CI, fuzz harnesses, RAF, and unused AEGIS families stay out.
- CI restores pinned Actions, sanitizer fuzz smoke, and isolated built-gem E2E.

- IO: all output paths use `write_all` (reject silent partial writes).
- Decrypt APIs accept `required_padding:` and can enforce Padmé / none / fixed /
  buckets after successful AEAD (wire format unchanged).
- Runtime dependency pinned to `pq_crypto = 0.6.4`.
- Resource limits applied to `inspect_envelope`, `rebuild_recipients`,
  `rotate_dek`, and `rebuild_recipients_file`.
- Default one-shot limits lowered to 64 MiB (use file/IO APIs for larger docs).
- Document that `rotate_dek` allocates a new `payload_id`.
- CI: Actions pinned by commit SHA; `permissions: contents: read`; fuzz and
  gem-smoke jobs restored.
- Repository hygiene: ignore `.DS_Store` and built binaries.

## 0.1.0


- AEGIS streaming state rejects `update`/`final` before `initialize` (`mode` guard).
- Encrypt path wipes the internal plaintext copy in `ensure` (caller buffers unchanged).
- CI: Actions pinned by commit SHA, `permissions: contents: read`, fuzz + gem-smoke jobs.
- Repository hygiene: `.DS_Store` / build artifacts ignored; no tracked binaries.

- Initial versioned `PQCSEAL1` envelope format.
- Multi-recipient DEK wrapping through `PQCrypto::HybridKEM` algorithm
  `:ml_kem_768_x25519_xwing` (pinned; not `CANONICAL_ALGORITHM`).
- Runtime dependency pinned to `pq_crypto ~> 0.6.4` so suite ID 1 cannot drift
  with a future 0.7+ line.
- Exact X-Wing size checks: public key 1216, ciphertext 1120, shared secret 32.
- HKDF-SHA256 key separation and AEGIS-256 payload/DEK encryption.
- Authenticated `padding_policy_id` in the immutable header (`none` / `padme` /
  fixed / buckets).
- String, IO, and atomic file APIs with strict EOF/size defaults; framed helpers
  `encrypt_frame_io` / `decrypt_frame_io` for embedded envelopes.
- Resource limits: `max_staging_bytes`, `max_plaintext_bytes`, `max_envelope_bytes`
  with safe defaults against payload amplification.
- Full-envelope Padmé padding.
- Recipient-section rebuild and DEK rotation operations.
- Public API hygiene: internal helpers (`unwrap_dek`, `derive_kek`, …) are
  private class methods.
- Malformed wire fields raise `FormatError` (not `InvalidConfigurationError`).
- `ResourceLimitError` for ceiling violations.
- Golden-vector suite pinning the X-Wing wire contract, the immutable-header
  byte layout, the payload AD derivation, and byte-identical one-shot vs
  incremental output under a deterministic RNG (`test/golden_vectors_test.rb`).
- Self-driving decrypt/parser fuzz job in CI (mutated and random envelopes),
  failing on any error outside the documented classes.
- CI GitHub Actions pinned by commit SHA; workflow `permissions` reduced to
  `contents: read`.
- Robust OpenSSL 3 selection for Homebrew Intel/Apple Silicon, `pkg-config`,
  environment roots, and explicit extconf paths.
- Remove OpenSSL 1.1 include paths inherited from Ruby 2.7 and link the selected
  OpenSSL 3 `libcrypto` by absolute path.
- Avoid unreliable OpenSSL link probes in legacy Ruby 2.7 `mkmf`; verify headers
  at configure time and the linked runtime in the extension initializer.
- Disable Minitest's parallel executor only in the ASan job (`N=0`) to avoid a
  known teardown conflict caused by preloading ASan into an otherwise unsanitized
  Ruby executable.

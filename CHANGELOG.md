# Changelog

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

# Changelog

## 0.1.4

Wire format v1, the public API and the error classes are unchanged. The frozen
golden envelope (`test/frozen_envelope_test.rb`) is byte-identical.

### Security

- **Native arguments converted before use.** `require_length` converted a
  `#to_str` argument into a local copy only, so the caller then read
  `RSTRING_PTR` of the original, non-String object (segfault under ASan/UBSan).
  All arguments are now converted with `StringValue` first, then validated.
- **No length check before a later `#to_str` callback.** The key length was
  validated before the nonce was converted; a nonce `#to_str` could shrink the
  key and the following 32-byte copy read out of bounds. Validation now happens
  only after every conversion.
- **Authentication error class pinned for GC compaction.** The cached
  `AuthenticationError` VALUE was not registered with the GC; after
  `GC.compact` raising it could crash. It is now a registered root.
- **AEGIS operations without the GVL use private C buffers** for the inputs and
  output. The extension creates the Ruby result with the GVL after the operation,
  then wipes and frees the C buffers.
- **Interrupts after a GVL-free section are handled.** Work runs under
  `rb_protect`; key copies and snapshots are wiped and outputs cleared before a
  pending `Thread#raise`/`kill` is re-raised. An interrupted or failed
  incremental update finalizes the AEGIS state, so it can no longer emit or
  accept a tag over data the caller never received.
- **AEGIS state locking uses `atomic_bool`** with acquire/release ordering, as in
  `pq_crypto` 0.6.8. `Encryptor`/`Decryptor` cannot be `dup`ed or `clone`d.
- **Effective zeroization.** `Secrets.wipe!` used `String#replace`, which frees
  the old buffer without clearing it. Wiping now goes through `Native.wipe`
  (in-place `OPENSSL_cleanse` after `rb_str_modify`). Parsers copy fields with
  `unpack1` instead of `byteslice`, so decrypted plaintext is not kept alive in
  hidden copy-on-write roots, and the private-metadata copy owns its buffer.
- File recipient rebuilds keep rejecting trailing bytes after the envelope.
- Stream encryption keeps caller-owned input buffers intact. Stream decryption
  uses the normalized chunk size after authentication.
- Extension built with `-fstack-protector-strong` and, when the toolchain does
  not already define it, `-D_FORTIFY_SOURCE=2`.

### Changed

- C extension split into `pqs_core.{c,h}` and Ruby bindings. HKDF-SHA256 uses
  OpenSSL 3 `EVP_MAC`.
- Vendored sources and their checksum match the pinned upstream
  `libaegis` 0.10.3 archive.
- Ruby library refactored into small objects (header/section/inner codecs with a
  declarative header layout, encryption plans, stanza sealing/opening, streaming
  writers and readers). The public String and IO APIs retain their Ruby
  keyword signatures.
- `PQC_SEAL_SANITIZE` accepts a sanitizer list (`1` still means
  `address,undefined`).
- `extconf.rb` restructured into `PQCSealBuild` modules; OpenSSL selection is
  unchanged.
- Development dependencies moved from the gemspec to the Gemfile.
- Internal helpers changed shape: `Format.split_slot(slot)` no longer takes the
  slot size, `Format.validate_capacity!` no longer checks the recipient count
  (`Format.validate_recipient_count!` does), `Format.parse_verified_inner` and
  the `Binary.read_*` helpers were removed, and implementation classes that were
  accidentally public (`OneShotEncryptor`, `OneShotOpener`, `RecipientRebuilder`,
  `DekRotator`) are now private constants. `IOAPI::DEFAULT_CHUNK_SIZE` remains.

### Testing

- Ruby regression tests cover native arguments, GC, concurrent updates and the
  IO cases above. CI also runs the Ruby-independent C tests under ASan and UBSan.

## 0.1.3

- Runtime dependency relaxed from `pq_crypto = 0.6.4` to `pq_crypto ~> 0.6`
  so patch/minor releases on the 0.6 line (including 0.6.7) resolve without a
  Seal bump. Wire suite 1 remains pinned by algorithm id and exact
  key/ciphertext/shared-secret sizes inside Seal; do not treat this as carte
  blanche for a future `1.x` / breaking KEM wire change.

## 0.1.2

### Security

- **Default padding enforcement on decrypt.** `decrypt` / `open` / `decrypt_io` /
  `decrypt_file` now default to `required_padding: :from_header`. Padmé / none
  get a full canonical size check from authenticated lengths. Fixed / buckets
  are not self-describing on the wire, so `:from_header` only accepts the
  authenticated policy id (envelope still opens); pass
  `required_padding: { to: N }` / `{ buckets: [...] }` for full target
  enforcement. Pass `required_padding: false` to opt out entirely.
- **RUP-safe IO staging.** `decrypt_io` / `decrypt_file` / DEK rotation stage
  **ciphertext** on the temporary 0600 file and only materialise plaintext after
  the AEGIS tag verifies (second pass). Unauthenticated plaintext is no longer
  written to disk before authentication.
- **Honest recipient ACL API.** Removed `drop_recipient_stanza` and
  `drop_recipient_stanza_file`. Those names suggested revocation while old copies
  and the DEK remain valid. Use `rebuild_recipients` / `rebuild_recipients_file`
  with the application's complete authoritative ACL for the current canonical
  copy only; use `rotate_dek` when a new payload key is required.
- **Capacity / slot growth path.** `recipient_capacity` and `slot_size` remain
  immutable in the payload header for a given envelope, but `rotate_dek` /
  `rotate_dek_file` now accept optional `recipient_capacity:` and `slot_size:`
  overrides because they re-encrypt the authenticated plaintext under a new DEK.
- **At-rest draft pinning documented.** SECURITY.md / FORMAT.md / VENDORING.md
  state that suite 1 and content suite 1 are pinned to X-Wing draft-10 and
  AEGIS-256 (IETF CFRG draft-18 vectors via libaegis 0.10.3), not to future RFC
  text. External KATs are referenced; self-generated golden vectors pin Seal's
  own wire layout only.
- **CI / release hygiene matched to claims.** Workflow Actions pinned by full
  commit SHA, top-level `permissions: contents: read`, and jobs for fuzz,
  gem-smoke, and `release_contract_check`. `.DS_Store` is gitignored; the
  release-contract checker rejects tracked copies.

### Breaking (0.1.x experimental)

- Default `required_padding` is `:from_header` (was effectively off / `nil`).
- `drop_recipient_stanza` / `drop_recipient_stanza_file` removed from the public API.

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

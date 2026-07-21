# Vendored cryptography

`ext/pq_crypto_seal/vendor/libaegis/src` contains the C sources corresponding to
libaegis 0.10.3.

- Upstream: https://github.com/aegis-aead/libaegis
- Tag: `0.10.3`
- Tag commit: `0bb1639`
- Official tag archive SHA-256: `2f2682c1d08d9a5510caca1c82e3f8ea91f7085fef2ecbed0c398b2a921c79b1`
- License: MIT
- KATs exercised by this gem: CFRG AEGIS draft-18 vectors in
  `test/aegis_vectors_test.rb` (content suite 1). Wire behaviour is pinned to
  this snapshot, not to a future RFC that may diverge.

X-Wing / MLKEM768-X25519 wrap suite 1 is supplied by runtime dependency
`pq_crypto = 0.6.4` (not vendored here). External draft-10 decapsulation KATs
live in `test/fixtures/xwing-draft-10-vector-*.json`.

The complete source snapshot is retained, while the Ruby extension compiles only the AEGIS-256 and common implementation files it exposes. No system libaegis is
loaded at runtime. Update the version, archive checksum, source snapshot, KATs,
and cross-backend tests together.

The git tree keeps the full upstream snapshot so `script/vendor_libs.rb --check`
can prove byte-identity against the audited archive. The published gem package
ships only the AEGIS-256 family plus shared `common`/`include` sources required
to compile the extension (see `pq_crypto-seal.gemspec`); unused families and RAF
remain in the repository for provenance and are not loaded at runtime.

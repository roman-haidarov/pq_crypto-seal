# Vendored cryptography

`ext/pq_crypto_seal/vendor/libaegis/src` contains the C sources corresponding to
libaegis 0.10.3.

- Upstream: https://github.com/aegis-aead/libaegis
- Tag: `0.10.3`
- Tag commit: `0bb1639`
- Official tag archive SHA-256: `2f2682c1d08d9a5510caca1c82e3f8ea91f7085fef2ecbed0c398b2a921c79b1`
- License: MIT

The complete source snapshot is retained, while the Ruby extension compiles only the AEGIS-256 and common implementation files it exposes. No system libaegis is
loaded at runtime. Update the version, archive checksum, source snapshot, KATs,
and cross-backend tests together.

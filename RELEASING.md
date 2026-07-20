# Releasing

1. Run `bundle exec ruby script/vendor_libs.rb --check`.
2. Confirm `pq_crypto` dependency remains `= 0.6.4` and `WRAP_KEM_ALGORITHM`
   is still `:ml_kem_768_x25519_xwing` with the documented sizes.
3. Run the full CI matrix and sanitizer job.
4. Build with `gem build pq_crypto-seal.gemspec`.
5. Install the exact built gem into an empty `GEM_HOME` together with the
   supported `pq_crypto` gem and run String and File round trips.
6. Confirm golden envelope vectors and pinned X-Wing wire-contract checks in
   `test/golden_vectors_test.rb` pass, and that the CI fuzz job is green.
7. Publish only from a signed tag through RubyGems Trusted Publishing.

Vendored libaegis sources are pinned by archive SHA-256 and a deterministic
source-tree digest (`vendor/libaegis/TREE_SHA256`). The full upstream snapshot
ships intact — including families and the RAF sources that this gem does not
compile — so `script/vendor_libs.rb --check` can prove the vendored tree is
byte-identical to the audited archive. Never delete vendored files to slim the
gem; that would break the provenance guarantee. Never update the snapshot
without rerunning official KATs, cross-backend equivalence checks, envelope
golden vectors, and fuzz tests.

The golden vectors fix every value this gem controls (recipient keys, DEK,
nonces, section id, padding bytes, metadata, plaintext) and assert the derived
header bytes, associated data, and one-shot/incremental equivalence. A fully
frozen "plaintext to exact bytes" vector is intentionally not asserted for the
KEM ciphertext region, because X-Wing encapsulation randomness originates inside
`pq_crypto` and is not injectable here; the wire-contract check pins its exact
sizes and round-trip instead.

The ASan job sets `detect_leaks=0` because ASan is preloaded into an otherwise
unsanitized Ruby interpreter; host-process allocator noise would otherwise fail
the job. Memory-safety errors still abort via `halt_on_error`.


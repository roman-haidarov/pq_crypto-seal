# Releasing

1. Run `bundle exec ruby script/vendor_libs.rb --check`.
2. Confirm `pq_crypto` dependency remains `~> 0.6` and `WRAP_KEM_ALGORITHM`
   is still `:ml_kem_768_x25519_xwing` with the documented sizes.
3. Run `bundle exec ruby script/release_contract_check.rb` (also enforced in CI).
4. Run the full CI matrix (`test`, `sanitize`, `fuzz`, `release_contract`,
   `gem-smoke`).
5. Build with `gem build pq_crypto-seal.gemspec`.
6. Re-run the release-contract checker against the built gem path.
7. Install the exact built gem into an empty `GEM_HOME` together with the
   supported `pq_crypto` gem and run String and File round trips.
8. Confirm golden envelope vectors, X-Wing draft-10 KATs, and AEGIS draft-18
   KATs pass, and that the CI fuzz job is green.
9. Create an annotated, signed tag at the reviewed commit. Use the gem version
   as the tag name and verify the signature before pushing the tag.

   ```bash
   version=$(ruby -r./lib/pq_crypto/seal/version -e 'puts PQCrypto::Seal::VERSION')
   git tag -s "$version" -m "pq_crypto-seal $version"
   git verify-tag "$version"
   ```

10. Build and smoke-test the gem from a clean checkout of the verified tag.
    Record the SHA-256 of that artifact. For RubyGems publication, configure
    the [Trusted Publisher](https://guides.rubygems.org/trusted-publishing/)
    and its release workflow before uploading the tested artifact. The CI
    workflow verifies the source and gem build.

Vendored libaegis sources are pinned by archive SHA-256 and a deterministic
source-tree digest (`vendor/libaegis/TREE_SHA256`). The repository and source
archive retain upstream's full `src` tree and license for provenance.
`script/vendor_libs.rb --check` verifies this snapshot against its pinned tree
digest. The gem includes the AEGIS-256 sources and shared files used by the
extension. Rerun official KATs, cross-backend equivalence checks, envelope
golden vectors, and fuzz tests whenever updating the snapshot.

The frozen envelope test supplies a published X-Wing encapsulation result and
deterministic randomness for Seal. It checks the digest of the complete envelope
for both one-shot and streaming encryption. Other golden tests cover header
bytes, associated data and recipient behaviour.

The Ruby sanitizer step sets `detect_leaks=0` because ASan runs inside an
otherwise unsanitized interpreter. Memory-safety errors still abort via
`halt_on_error`. The step sets `use_sigaltstack=0` so ASan leaves Ruby's
per-thread alternate signal stack intact when threads exit. It also sets
`detect_stack_use_after_return=0` because the hosted Ruby GC cannot discover
live `VALUE`s on ASan's fake stack. See [Ruby issue #20310](https://bugs.ruby-lang.org/issues/20310).
The standalone C sanitizer step uses the defaults in `test/c_core/run.sh`,
including stack-use-after-return checking.


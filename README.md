# pq_crypto-seal

Post-quantum envelope encryption for Ruby 2.7.1+.

The gem turns `pq_crypto`'s hybrid KEM into practical document encryption:

```text
MLKEM768-X25519 shared secret → HKDF-SHA256 → KEK → wrap random DEK
random DEK → AEGIS-256 → document
```

`libaegis` 0.10.3 is vendored and compiled into the extension. The existing
`pq_crypto` gem supplies the hybrid KEM and OpenSSL-backed primitives.

> **Status:** 0.1.1 is experimental cryptographic software; format v1; not
> independently audited. Read `SECURITY.md` before using it for irreplaceable data.
>
> `wrap_suite_id = 1` is pinned to `:ml_kem_768_x25519_xwing` and `pq_crypto = 0.6.4`.

## Installation

```ruby
gem "pq_crypto", "~> 0.6.4"
gem "pq_crypto-seal", "~> 0.1.0"
```

Ruby `>= 2.7.1` and OpenSSL `>= 3.0` development files are required for a
source build.

On macOS, `extconf.rb` automatically searches Homebrew `openssl@3` on both
Apple Silicon and Intel installations. If OpenSSL 3 is installed in a custom
location, configure it explicitly:

```bash
brew install openssl@3
bundle config set --local build.pq_crypto-seal \
  "--with-openssl-dir=$(brew --prefix openssl@3)"
bundle exec rake clean compile
```

`OPENSSL_ROOT_DIR` and `OPENSSL_DIR` are also supported. An explicit
`--with-openssl-dir`, `--with-openssl-include`, or `--with-openssl-lib` always
takes precedence over automatic discovery.

## String API

```ruby
require "pq_crypto/seal"

alice = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
bob   = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)

sealed = PQCrypto::Seal.encrypt(
  image_bytes,
  to: [alice.public_key, bob.public_key],
  metadata: { mime: "image/png" }.to_json,
  public_metadata: "tenant-7",
  recipient_capacity: 4,
  slot_size: 2048,
  padding: :padme
)

opened = PQCrypto::Seal.open(sealed, with: alice) # keypair supplies secret + public hint material
opened.data
opened.metadata
opened.public_metadata

PQCrypto::Seal.decrypt(sealed, with: bob)
```

All random keys and nonces are generated internally. There is no public API for
supplying a DEK or nonce. Because scoped hint lookup needs the matching public
key, `with:` accepts a `HybridKEM::Keypair`. When keys are stored separately:

```ruby
credentials = PQCrypto::Seal.credentials(
  secret_key: loaded_secret_key,
  public_key: loaded_public_key
)
PQCrypto::Seal.decrypt(sealed, with: credentials)
```

## Files and IO

```ruby
PQCrypto::Seal.encrypt_file(
  "scan.tiff",
  "scan.tiff.pqcseal",
  to: alice.public_key
)

PQCrypto::Seal.decrypt_file(
  "scan.tiff.pqcseal",
  "restored.tiff",
  with: alice
)
```

`encrypt_io` accepts the exact plaintext `size:`. `decrypt_io` stages the entire
unauthenticated inner frame to a mode-0600 temporary file and copies content to
the caller's output only after the final AEGIS tag is valid.

## Recipients and key lifecycle

The envelope intentionally does not contain an authoritative list of recipient
public keys. The application owns the ACL. Any complete recipient-section
rewrite therefore receives the full list:

```ruby
updated = PQCrypto::Seal.rebuild_recipients(
  sealed,
  with: alice,
  recipients: [alice.public_key, carol.public_key]
)
```

`add_recipient(..., recipient:, current_recipients:)` still requires the
complete current ACL and rebuilds all slots.
`drop_recipient_stanza(..., remaining_recipients:)` describes exactly what it
does. It does **not** revoke plaintext, a DEK, or old copies already obtained.

```ruby
rotated = PQCrypto::Seal.rotate_dek(
  sealed,
  with: alice,
  recipients: [alice.public_key, carol.public_key]
) # preserves the existing envelope size by default
```

`rebuild_recipients` preserves the DEK and encrypted payload. It is an
operational migration of the current canonical copy, not protection against old
saved envelopes. `rotate_dek` creates a new DEK, a **new payload_id**, and re-encrypts the payload; it
still cannot erase knowledge from prior copies. Rotation preserves the current
final envelope size by default (`padding: :preserve`); pass `:padme`, `:none`, or
an explicit padding policy to recalculate it.

## Wire-format v1

The exact bytes are implemented in `PQCrypto::Seal::Format`:

```text
immutable payload header
  magic "PQCSEAL1"
  version
  content_suite_id = AEGIS-256 payload profile
  lookup_mode = payload-scoped recipient hint
  payload_id, payload_nonce
  recipient_capacity, slot_size
  padded_inner_length
  public metadata

mutable recipient section
  wrap_suite_id = MLKEM768-X25519 + HKDF-SHA256 + AEGIS-256 wrap
  random section_id (changes on every complete rebuild)
  fixed-capacity, fixed-size slots

slot
  recipient_hint
  1120-byte hybrid KEM ciphertext
  wrap nonce
  wrapped 32-byte DEK
  32-byte tag
  authenticated random slot padding

AEGIS-encrypted inner frame
  authenticated content length and private metadata length
  private metadata
  content
  encrypted Padmé padding

32-byte payload tag
```

`content_suite_id` and `wrap_suite_id` are deliberately independent. A recipient
section can be rebuilt without changing payload AD as long as the new wrapping
stanza fits the immutable `slot_size`.

Defaults:

```text
slot_size:          2048 bytes (configurable 2048..8192, multiple of 256)
recipient_capacity: 4 (maximum 32; never derived automatically from ACL size)
padding:            Padmé over the complete final envelope size
```

The payload-and-section-scoped recipient hint avoids a stable global recipient identifier and prevents stable hints from revealing real slots across recipient-section rebuilds.
Anyone who already knows a candidate public key can test for its presence. No
formal recipient anonymity is claimed.

The wrapping KEM follows the MLKEM768-X25519/X-Wing construction, targeting
approximately 128-bit security. ML-KEM-768 supplies conservative margin; the
full hybrid suite is not advertised as NIST category 3.

## Envelope identity

`PQCrypto::Seal.digest(envelope)` is SHA-256 over the **complete** envelope
bytes. The recipient section is intentionally mutable, so
`rebuild_recipients` / `rotate_dek` change the digest even when the encrypted
payload is unchanged. Use `opened.payload_id` (or `inspect_envelope`) for a
stable document identifier.

High `recipient_capacity` makes encryption slower: every empty slot still runs
a full X-Wing encapsulation against a disposable keypair.

## Tests

```bash
bundle install
bundle exec rake
```

Set `PQC_SEAL_SANITIZE=1` when compiling under ASan/UBSan. The suite covers
AEGIS one-shot/incremental equivalence, tampering, multi-recipient opening,
full-envelope padding, recipient rebuilds, staged file publication, and parser
limits.


## Padding enforcement on decrypt

After AEAD verification you may require a padding policy:

```ruby
PQCrypto::Seal.decrypt(envelope, with: credentials, required_padding: :padme)
PQCrypto::Seal.decrypt(envelope, with: credentials, required_padding: :from_header)
PQCrypto::Seal.decrypt(envelope, with: credentials, required_padding: { to: 4096 })
```

Omitting `required_padding` keeps padding enforcement optional. When supplied,
the decryptor verifies both the authenticated policy id and the canonical target
computed from the authenticated content and metadata lengths. Fixed and bucket
policies require the expected target or bucket list from the application.

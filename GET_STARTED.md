# Getting started

## Build prerequisites

Ruby 2.7.1+ and OpenSSL 3.0+ development files are required. On macOS the
build automatically searches Homebrew `openssl@3`. For a custom installation:

```bash
bundle config set --local build.pq_crypto-seal \
  "--with-openssl-dir=$(brew --prefix openssl@3)"
bundle exec rake clean compile
```

```ruby
require "pq_crypto/seal"

recipient = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
envelope = PQCrypto::Seal.encrypt("secret bytes", to: recipient.public_key)
plaintext = PQCrypto::Seal.decrypt(envelope, with: recipient)
```

For files, use `encrypt_file` and `decrypt_file`; decryption stages ciphertext,
verifies the AEGIS tag, then materialises plaintext before publishing. Use
`recipient_capacity` and `slot_size` as long-lived application policy values:
both are stored in the immutable payload header. To grow them after encryption,
call `rotate_dek` / `rotate_dek_file` with new `recipient_capacity:` /
`slot_size:` (full re-encryption under a new DEK).

Recipient-section rebuilds always require the application's complete,
authoritative public-key ACL. They do not revoke access to plaintext, the DEK,
or old envelope copies. Prefer `rebuild_recipients` over inventing “drop”
helpers. Use `rotate_dek` when a new payload key is required.

Decrypt defaults to `required_padding: :from_header`: Padmé/none get a full size
check; fixed/buckets open with a policy-id check (pass `{ to: }` / `{ buckets: }`
for full target enforcement).

## Large documents

Default one-shot limits are 64 MiB (`max_plaintext_bytes` / related staging and
envelope ceilings). For larger objects use `encrypt_file` / `decrypt_file` or
`encrypt_io` / `decrypt_io` and raise the limits explicitly, for example:

```ruby
PQCrypto::Seal.decrypt_file(src, dst, with: credentials, max_plaintext_bytes: 512 * 1024 * 1024)
```

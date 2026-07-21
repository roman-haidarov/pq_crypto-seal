# Security

This project has not received an independent cryptographic or implementation
audit. Do not treat version 0.1.2 as a substitute for a reviewed storage design.

Experimental cryptographic software; format v1; not independently audited.

## Threat model

The v1 format protects confidentiality and integrity of the **payload** when an
attacker obtains a passive copy of envelopes but not a recipient secret key.

Successful opening authenticates:

- the immutable payload header
- the selected recipient stanza that yielded the DEK
- the encrypted inner frame (private metadata + content + encrypted padding)

Successful opening does **not** authenticate:

- the integrity of other recipients' stanzas
- the completeness or correctness of the application ACL
- absence of rollback against a replaceable canonical envelope

It does not claim recipient anonymity. Anyone who already knows a candidate
public key can test for its presence via the scoped recipient hint.

### Recipients, ACL ownership, and non-revocation

The envelope is **not** an authoritative ACL. The application must store and
synchronise the complete recipient public-key list itself. Every recipient-section
rewrite (`rebuild_recipients` / `add_recipient` and the `*_file` variants)
requires that full list and only protects the **current canonical copy**.

Rebuilding the recipient section does **not** revoke:

- plaintext already opened by a removed party
- the DEK (unchanged across rebuilds)
- older envelope bytes the removed party already copied

`rotate_dek` allocates a new DEK and a new `payload_id`, re-encrypts the payload,
and still cannot erase knowledge from prior copies. Treat any former recipient
who retained an old envelope and their secret key as still able to open that old
copy.

There is intentionally **no** `drop_recipient_*` API: a “drop” name encourages
the false belief that access was revoked.

### Capacity and slot size

`recipient_capacity` and `slot_size` are stored in the **immutable** payload
header and are associated-data for the payload AEAD. They cannot change for a
given encrypted payload without full re-encryption. Use `rotate_dek` /
`rotate_dek_file` with optional `recipient_capacity:` / `slot_size:` when the
application needs a larger slot table after authenticating the current payload.

## Side channels

Recipient lookup short-circuits slots whose hint does not match. The number of
full KEM decapsulations therefore depends on how many slots share the expected
hint. Against a purely passive adversary holding only the envelope bytes this is
out of scope. Local timing, cache, or power side channels on a machine that
already holds a recipient secret key are not mitigated. `AmbiguousRecipientStanzas`
is raised when more than one slot opens successfully.

Caller-owned plaintext and metadata buffers are not wiped by the encrypt path;
callers that need residual-data hygiene must clear their own buffers.
`Opened#data` / `Opened#metadata` returned from `open` are the caller's
responsibility after use.


## payload_id stability

`payload_id` is stable across `rebuild_recipients` / add operations.
`rotate_dek` re-encrypts the payload with a fresh DEK and **allocates a new
`payload_id`** — treat the result as a new document identity. Applications that
need a stable external id across DEK rotation must track it outside the envelope.

## Padding policy enforcement

The authenticated header carries `padding_policy_id`. Decrypt/open APIs default
to `required_padding: :from_header`:

- Padmé / none — full check of policy id **and** canonical size from
  authenticated inner lengths
- fixed / buckets — policy id only (targets are not on the wire); pass
  `required_padding: { to: N }` or `{ buckets: [...] }` for full target
  enforcement

Pass `required_padding: false` only when the application deliberately skips
length-hiding checks.

## Envelope digests

`Seal.digest` hashes the complete envelope, including the mutable recipient
section. Prefer `payload_id` (exposed on `Opened` and `Inspection`) when a
stable document identifier is required.

## Resource limits

Untrusted envelopes declare `padded_inner_length` as a uint64. Decrypt APIs
enforce default ceilings (`max_staging_bytes`, `max_plaintext_bytes`,
`max_envelope_bytes`) so a sender who knows a recipient public key cannot force
unbounded staging or disk amplification before the final AEGIS tag fails.

- `max_staging_bytes` / `max_envelope_bytes` are checked **before** AEAD
  verification (pre-auth).
- `max_plaintext_bytes` is enforced **after** the payload tag verifies
  (post-auth), because the real content length is authenticated inside the
  inner frame.

Applications may raise the limits explicitly when larger objects are required.

## Staging (RUP)

Large decryptions stage the **ciphertext** inner frame in a mode-0600 temporary
file. On Unix the file is unlinked immediately after opening. Intermediate AEGIS
streaming plaintext is wiped in memory and is not written to disk until the
final tag has verified; only then is verified plaintext materialised for
parsing and publication. Platforms that cannot unlink an open file, filesystem
snapshots, and storage-layer forensics may still retain remnants (including
ciphertext); use a suitably protected staging filesystem.

## Wire suite pinning and draft risk

At-rest envelopes outlive draft documents. Suite identifiers freeze behaviour
independent of future RFC text:

| Component | Pin |
|---|---|
| `wrap_suite_id = 1` | MLKEM768-X25519 / X-Wing **draft-10** compatible via `pq_crypto = 0.6.4` algorithm `:ml_kem_768_x25519_xwing` (PK 1216, CT 1120, SS 32) |
| `content_suite_id = 1` | AEGIS-256, 32-byte nonce/tag, inner-frame-v1, via vendored **libaegis 0.10.3** |
| AEGIS KATs | CFRG AEGIS draft-18 positive/negative vectors in `test/aegis_vectors_test.rb` |
| X-Wing KATs | draft-10 decapsulation vectors in `test/fixtures/xwing-draft-10-vector-*.json` (see `test/xwing_kat_test.rb`) |

Seal does **not** follow `HybridKEM::CANONICAL_ALGORITHM`; a future change of
that constant must not alter suite 1 wire bytes. Always generate keys with
`PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)`.

If a final RFC diverges from these pins, a new suite id (and migration) is
required; existing `PQCSEAL1` / suite-1 envelopes remain defined by this pin,
not by later drafts. Envelope golden vectors in `test/golden_vectors_test.rb`
are generated under a deterministic RNG to pin **Seal-controlled** layout and
labels; they are not a substitute for the external KEM/AEAD KATs above.

Report vulnerabilities privately to the repository owner.

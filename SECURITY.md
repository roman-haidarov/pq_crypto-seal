# Security

This project has not received an independent cryptographic or implementation
audit. Do not treat version 0.1.1 as a substitute for a reviewed storage design.

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

Removing a recipient stanza does not revoke plaintext, a DEK, or an older copy
already obtained by that recipient. Rebuilding recipient stanzas protects the
current copy only. Rotating the DEK creates a new protected version but cannot
remove knowledge from older copies.

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

`payload_id` is stable across `rebuild_recipients` / add / drop operations.
`rotate_dek` re-encrypts the payload with a fresh DEK and **allocates a new
`payload_id`** — treat the result as a new document identity. Applications that
need a stable external id across DEK rotation must track it outside the envelope.

## Padding policy enforcement

The authenticated header carries `padding_policy_id` only. Receivers that require
a specific length-hiding policy should pass `required_padding:` to decrypt/open
(for example `required_padding: :padme` or `required_padding: :from_header`).
The receiver then checks both the policy id and the canonical target computed from
authenticated inner lengths. Without that argument the field is informational.

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

## Staging

Large decryptions stage unauthenticated plaintext in a mode-0600 temporary file.
On Unix the file is unlinked immediately after opening. The staged bytes are
never returned or published before the final AEGIS tag is verified. Platforms
that cannot unlink an open file, filesystem snapshots, and storage-layer
forensics may still retain remnants; use a suitably protected staging filesystem.

## Wire suite pinning

`wrap_suite_id = 1` is permanently bound to MLKEM768-X25519 / X-Wing (draft-10
compatible) with fixed public-key (1216), ciphertext (1120), and shared-secret
(32) sizes, as implemented by `pq_crypto = 0.6.4`. Seal does not follow
`HybridKEM::CANONICAL_ALGORITHM`; a future change of that constant must not
alter suite 1 wire bytes. Always generate keys with
`PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)`.

Report vulnerabilities privately to the repository owner.

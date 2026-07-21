# PQCSEAL1 wire format

All integers are unsigned big-endian. Parsers reject trailing bytes, unknown
flags, unsupported suites, noncanonical lengths, and arithmetic overflow before
allocating from untrusted lengths.

## Immutable payload header

| Field | Size |
|---|---:|
| magic (`PQCSEAL1`) | 8 |
| format version (`1`) | 1 |
| header length | 4 |
| content suite ID (`1`) | 2 |
| lookup mode (`1`, scoped hint) | 1 |
| flags (`0`) | 2 |
| padding policy ID | 1 |
| payload ID | 32 |
| payload nonce | 32 |
| recipient capacity | 2 |
| slot size | 2 |
| padded inner length | 8 |
| public metadata length | 4 |
| public metadata | variable |

Padding policy IDs:

| ID | Meaning |
|---:|---|
| 0 | none |
| 1 | Padmé over the complete final envelope size |
| 2 | fixed target (`padding: { to: N }`) |
| 3 | application buckets (`padding: { buckets: [...] }`) |

The payload AEGIS associated data is exactly:

```text
SHA-256(exact immutable payload header bytes)
```

Content suite `1` fixes AEGIS-256 (libaegis 0.10.3; CFRG draft-18 KATs), a
32-byte nonce, a 32-byte tag, and inner-frame-v1. The padding policy ID records
how the final envelope length was chosen; it is authenticated as part of the
header.

## Mutable recipient section

| Field | Size |
|---|---:|
| wrap suite ID (`1`) | 2 |
| random section ID | 32 |
| fixed slots | `recipient_capacity * slot_size` |

Every complete recipient-section rebuild creates a new random section ID and
recreates all real and dummy slots. Mixed wrapping suites are forbidden.

Wrap suite `1` fixes MLKEM768-X25519/X-Wing **draft-10**-compatible encapsulation
(`pq_crypto = 0.6.4` algorithm `:ml_kem_768_x25519_xwing`), HKDF-SHA256, AEGIS-256
DEK wrapping, and 32-byte wrap nonces/tags. The suite id freezes that behaviour
for at-rest data even if a later RFC text diverges. Exact sizes:

| Value | Bytes |
|---|---:|
| public key | 1216 |
| KEM ciphertext | 1120 |
| shared secret | 32 |

## Slot layout for wrap suite 1

| Field | Size |
|---|---:|
| recipient hint | 32 |
| KEM ciphertext | 1120 |
| wrap nonce | 32 |
| encrypted DEK | 32 |
| wrap tag | 32 |
| authenticated random slot padding | `slot_size - 1248` |

The hint is:

```text
SHA-256(
  "PQC-SEAL-V1-RECIPIENT-HINT\0" ||
  payload_id || section_id || uint16(wrap_suite_id) || canonical_public_key
)
```

The 32-byte KEK is derived with RFC 5869 HKDF-SHA256. Salt is the RFC 5869
default of 32 zero bytes (HashLen zeros). `info` is:

```text
"PQC-SEAL-V1-WRAP-KEY\0" ||
payload_id || section_id || uint16(wrap_suite_id) || uint16(slot_index)
```

The AEGIS AD for wrapping is:

```text
SHA-256(
  "PQC-SEAL-V1-WRAP-AD\0" ||
  payload_header_hash || section_id || uint16(slot_index) ||
  uint16(wrap_suite_id) || recipient_hint || slot_padding
)
```

Dummy slots execute the same full KEM/HKDF/AEGIS pipeline against disposable
keypairs and random dummy DEKs. No recipient count is serialized.

## Encrypted inner frame

| Field | Size |
|---|---:|
| inner version (`1`) | 1 |
| inner flags (`0`) | 1 |
| real content length | 8 |
| private metadata length | 4 |
| private metadata | variable |
| content | variable |
| random encrypted padding | variable |

The final field following the encrypted inner frame is the 32-byte payload tag.
The padding amount is chosen so the size of the complete final envelope reaches
the configured Padmé/fixed/bucket target.

During incremental decryption, all inner bytes are untrusted until the final tag
has been verified. Implementations stage the complete **ciphertext** inner frame,
authenticate the tag, materialise plaintext only after verification, then parse
lengths and publish content.

## Defaults

```text
slot_size:          2048 bytes (configurable 2048..8192, multiple of 256)
recipient_capacity: 4 (maximum 32; never derived automatically from ACL size)
padding:            Padmé over the complete final envelope size
max_staging_bytes:  ~1 GiB + private-metadata ceiling
max_plaintext_bytes:64 MiB by default
```

Parsers reject trailing bytes on the one-shot and default IO paths. Framed
stream consumers that intentionally embed one envelope inside a larger stream
must use `encrypt_frame_io` / `decrypt_frame_io`.


## Receiver-side padding checks (0.1.2+)

`padding_policy_id` is authenticated but does not by itself encode fixed targets
or bucket lists. Decrypt APIs default to `required_padding: :from_header`:

- Padmé / none — full canonical size enforcement
- fixed / buckets — accept authenticated policy id; full target checks need
  `required_padding: { to: N }` or `{ buckets: [...] }`

Pass `required_padding: false` to skip enforcement.

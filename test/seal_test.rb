# frozen_string_literal: true
require_relative "test_helper"

class SealTest < Minitest::Test
  def setup
    @alice = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    @bob = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
  end

  def test_multi_recipient_round_trip_and_padding
    data = ("image" * 10_000).b
    envelope = PQCrypto::Seal.encrypt(
      data, to: [@alice.public_key, @bob.public_key],
      metadata: "private", public_metadata: "public"
    )
    alice = PQCrypto::Seal.open(envelope, with: @alice)
    bob = PQCrypto::Seal.open(envelope, with: @bob)
    assert_equal data, alice.data
    assert_equal data, bob.data
    assert_equal "private", alice.metadata
    assert_equal "public", alice.public_metadata
    assert_equal PQCrypto::Seal::Format::PADDING_PADME, alice.padding_policy_id
    assert_operator envelope.bytesize, :>=, data.bytesize
  end

  def test_wrong_recipient_and_tampering_fail
    envelope = PQCrypto::Seal.encrypt("secret", to: @alice.public_key)
    stranger = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    assert_raises(PQCrypto::Seal::RecipientNotFoundError) do
      PQCrypto::Seal.decrypt(envelope, with: stranger)
    end
    broken = envelope.dup
    broken.setbyte(broken.bytesize - 1, broken.getbyte(-1) ^ 1)
    assert_raises(PQCrypto::Seal::AuthenticationError) do
      PQCrypto::Seal.decrypt(broken, with: @alice)
    end
  end

  def test_rebuild_recipients_preserves_payload
    envelope = PQCrypto::Seal.encrypt("document", to: @alice.public_key)
    rebuilt = PQCrypto::Seal.rebuild_recipients(
      envelope, with: @alice,
      recipients: [@alice.public_key, @bob.public_key]
    )
    assert_equal "document", PQCrypto::Seal.decrypt(rebuilt, with: @bob)
    assert_raises(PQCrypto::Seal::RecipientNotFoundError) do
      PQCrypto::Seal.decrypt(envelope, with: @bob)
    end
  end

  def test_rebuild_randomizes_entire_recipient_section
    envelope = PQCrypto::Seal.encrypt("document", to: @alice.public_key)
    rebuilt = PQCrypto::Seal.rebuild_recipients(
      envelope, with: @alice, recipients: [@alice.public_key]
    )
    original_info = PQCrypto::Seal.inspect_envelope(envelope)
    rebuilt_info = PQCrypto::Seal.inspect_envelope(rebuilt)
    assert_equal original_info.payload_id, rebuilt_info.payload_id
    refute_equal envelope, rebuilt
    assert_equal "document", PQCrypto::Seal.decrypt(rebuilt, with: @alice)
  end

  def test_padme_and_none_policy_ids
    data = "x" * 12_345
    metadata = "m" * 19
    envelope = PQCrypto::Seal.encrypt(data, to: @alice.public_key, metadata: metadata, padding: :padme)
    info = PQCrypto::Seal.inspect_envelope(envelope)
    assert_equal PQCrypto::Seal::Format::PADDING_PADME, info.padding_policy_id
    assert_equal data, PQCrypto::Seal.decrypt(envelope, with: @alice)

    none_env = PQCrypto::Seal.encrypt("hi", to: @alice.public_key, padding: :none)
    assert_equal PQCrypto::Seal::Format::PADDING_NONE,
                 PQCrypto::Seal.inspect_envelope(none_env).padding_policy_id
    assert_equal "hi", PQCrypto::Seal.decrypt(none_env, with: @alice)
  end

  def test_truncation_trailing_bytes_and_payload_tamper_fail
    envelope = PQCrypto::Seal.encrypt("secret" * 100, to: @alice.public_key)
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(envelope.byteslice(0, envelope.bytesize - 1), with: @alice)
    end
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(envelope + "x", with: @alice)
    end

    info = PQCrypto::Seal.inspect_envelope(envelope)
    payload_offset = info.envelope_bytes - info.padded_inner_length - PQCrypto::Seal::Format::TAG_BYTES
    broken = envelope.dup
    broken.setbyte(payload_offset, broken.getbyte(payload_offset) ^ 1)
    assert_raises(PQCrypto::Seal::AuthenticationError) do
      PQCrypto::Seal.decrypt(broken, with: @alice)
    end
  end

  def test_separately_loaded_credentials_and_duplicate_rejection
    credentials = PQCrypto::Seal.credentials(
      secret_key: @alice.secret_key, public_key: @alice.public_key
    )
    envelope = PQCrypto::Seal.encrypt("x", to: @alice.public_key)
    assert_equal "x", PQCrypto::Seal.decrypt(envelope, with: credentials)
    assert_raises(PQCrypto::Seal::InvalidConfigurationError) do
      PQCrypto::Seal.encrypt("x", to: [@alice.public_key, @alice.public_key])
    end
  end

  def test_rotate_dek_preserves_envelope_size_by_default
    envelope = PQCrypto::Seal.encrypt(
      "document" * 500, to: @alice.public_key, padding: { to: 20_000 }
    )
    rotated = PQCrypto::Seal.rotate_dek(
      envelope, with: @alice, recipients: [@alice.public_key, @bob.public_key]
    )
    assert_equal envelope.bytesize, rotated.bytesize
    assert_equal "document" * 500, PQCrypto::Seal.decrypt(rotated, with: @bob)
    assert_equal PQCrypto::Seal::Format::PADDING_FIXED,
                 PQCrypto::Seal.inspect_envelope(rotated).padding_policy_id
  end

  def test_capacity_is_fixed_policy
    assert_raises(PQCrypto::Seal::RecipientCapacityExceeded) do
      keys = 5.times.map { PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM).public_key }
      PQCrypto::Seal.encrypt("x", to: keys, recipient_capacity: 4)
    end
  end

  def test_internals_are_not_public
    refute PQCrypto::Seal.respond_to?(:unwrap_dek)
    refute PQCrypto::Seal.respond_to?(:derive_kek)
    refute PQCrypto::Seal.respond_to?(:build_slot)
    refute PQCrypto::Seal.respond_to?(:parse_envelope)
    refute PQCrypto::Seal.respond_to?(:wipe_string!)
    assert PQCrypto::Seal.respond_to?(:encrypt)
    assert PQCrypto::Seal.respond_to?(:decrypt)
    assert PQCrypto::Seal.respond_to?(:open)
    assert PQCrypto::Seal.respond_to?(:digest)
  end

  def test_resource_limit_rejects_huge_declared_inner
    envelope = PQCrypto::Seal.encrypt("tiny", to: @alice.public_key, padding: :none)
    assert_raises(PQCrypto::Seal::ResourceLimitError) do
      PQCrypto::Seal.decrypt(envelope, with: @alice, max_staging_bytes: 8)
    end
  end

  def test_malformed_capacity_is_format_error
    envelope = PQCrypto::Seal.encrypt("x", to: @alice.public_key, padding: :none)
    # capacity sits after magic(8)+ver(1)+hdrlen(4)+suite(2)+lookup(1)+flags(2)+pad_policy(1)+pid(32)+nonce(32)
    offset = 8 + 1 + 4 + 2 + 1 + 2 + 1 + 32 + 32
    broken = envelope.dup
    broken.setbyte(offset, 0xff)
    broken.setbyte(offset + 1, 0xff)
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(broken, with: @alice)
    end
  end

  def test_array_credentials_form
    envelope = PQCrypto::Seal.encrypt("array-cred", to: @alice.public_key, padding: :none)
    assert_equal "array-cred",
                 PQCrypto::Seal.decrypt(envelope, with: [@alice.secret_key, @alice.public_key])
  end

  def test_fixed_and_bucket_padding_policies
    fixed = PQCrypto::Seal.encrypt("x", to: @alice.public_key, padding: { to: 12_000 })
    assert_equal 12_000, fixed.bytesize
    assert_equal PQCrypto::Seal::Format::PADDING_FIXED,
                 PQCrypto::Seal.inspect_envelope(fixed).padding_policy_id
    assert_equal "x", PQCrypto::Seal.decrypt(fixed, with: @alice)

    bucketed = PQCrypto::Seal.encrypt("y", to: @alice.public_key, padding: { buckets: [8_000, 16_000, 32_000] })
    assert_includes [8_000, 16_000, 32_000], bucketed.bytesize
    assert_equal PQCrypto::Seal::Format::PADDING_BUCKETS,
                 PQCrypto::Seal.inspect_envelope(bucketed).padding_policy_id
    assert_equal "y", PQCrypto::Seal.decrypt(bucketed, with: @alice)
  end

  def test_digest_changes_on_recipient_rebuild
    envelope = PQCrypto::Seal.encrypt("stable-payload", to: @alice.public_key, padding: :none)
    d1 = PQCrypto::Seal.digest(envelope)
    rebuilt = PQCrypto::Seal.rebuild_recipients(
      envelope, with: @alice, recipients: [@alice.public_key, @bob.public_key]
    )
    d2 = PQCrypto::Seal.digest(rebuilt)
    refute_equal d1, d2
    assert_equal PQCrypto::Seal.open(envelope, with: @alice).payload_id,
                 PQCrypto::Seal.open(rebuilt, with: @alice).payload_id
  end

  def test_wrap_kem_algorithm_is_pinned
    assert_equal :ml_kem_768_x25519_xwing, PQCrypto::Seal::WRAP_KEM_ALGORITHM
    assert_equal 1216, PQCrypto::Seal::Format::XWING_PUBLIC_KEY_BYTES
    assert_equal 1120, PQCrypto::Seal::Format::XWING_CIPHERTEXT_BYTES
    assert_equal 32, PQCrypto::Seal::Format::XWING_SHARED_SECRET_BYTES
    refute PQCrypto::Seal::Format.const_defined?(:XWING_SECRET_KEY_BYTES)
  end

  def test_index_binding_prevents_naive_slot_duplication
    # wrap_ad / derive_kek bind slot_index, so byte-copying a real slot into
    # another index cannot open a second time for the same recipient.
    envelope = PQCrypto::Seal.encrypt(
      "ambig", to: @alice.public_key, recipient_capacity: 2, slot_size: 2048, padding: :none
    )
    header = PQCrypto::Seal::Format.parse_header(envelope)
    section_offset = header.raw.bytesize
    slots_offset = section_offset + 2 + PQCrypto::Seal::Format::SECTION_ID_BYTES
    slot0 = envelope.byteslice(slots_offset, header.slot_size)
    broken = envelope.dup
    broken[slots_offset + header.slot_size, header.slot_size] = slot0
    assert_equal "ambig", PQCrypto::Seal.decrypt(broken, with: @alice)
  end

  def test_two_valid_stanzas_for_same_recipient_are_ambiguous
    # Defense-in-depth: a crafted envelope with two correctly-built slots for
    # the same public key (different indices) must not pick an arbitrary DEK.
    envelope = PQCrypto::Seal.encrypt(
      "ambig", to: @alice.public_key, recipient_capacity: 2, slot_size: 2048, padding: :none
    )
    header, section, ciphertext, tag = PQCrypto::Seal.send(:parse_envelope, envelope)
    dek = PQCrypto::Seal.send(:unwrap_dek, header, section, @alice)
    crafted_section = PQCrypto::Seal.send(
      :build_recipient_section,
      recipients: [@alice.public_key, @alice.public_key],
      capacity: 2,
      slot_size: header.slot_size,
      payload_id: header.payload_id,
      header_hash: PQCrypto::Seal.const_get(:Native).sha256(header.raw),
      dek: dek,
      wrap_suite_id: PQCrypto::Seal::Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
    )
    crafted = header.raw + crafted_section + ciphertext + tag
    assert_raises(PQCrypto::Seal::AmbiguousRecipientStanzas) do
      PQCrypto::Seal.decrypt(crafted, with: @alice)
    end
  ensure
    PQCrypto::Seal.send(:wipe_string!, dek) if defined?(dek)
  end


  def test_required_padding_padme_accepts_honest_envelope
    env = PQCrypto::Seal.encrypt("pad-ok", to: @alice.public_key, padding: :padme)
    assert_equal "pad-ok", PQCrypto::Seal.decrypt(env, with: @alice, required_padding: :padme)
    assert_equal "pad-ok", PQCrypto::Seal.decrypt(env, with: @alice, required_padding: :from_header)
  end

  def test_required_padding_none_rejects_padme_envelope
    env = PQCrypto::Seal.encrypt("pad-bad", to: @alice.public_key, padding: :padme)
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(env, with: @alice, required_padding: :none)
    end
  end

  def test_required_padding_none_accepts_none_envelope
    env = PQCrypto::Seal.encrypt("plain", to: @alice.public_key, padding: :none)
    assert_equal "plain", PQCrypto::Seal.decrypt(env, with: @alice, required_padding: :none)
  end

  def test_rotate_dek_changes_payload_id
    env = PQCrypto::Seal.encrypt("rot", to: @alice.public_key, padding: :none)
    before = PQCrypto::Seal.inspect_envelope(env).payload_id
    rotated = PQCrypto::Seal.rotate_dek(env, with: @alice, recipients: [@alice.public_key], padding: :none)
    after = PQCrypto::Seal.inspect_envelope(rotated).payload_id
    refute_equal before, after
    assert_equal "rot", PQCrypto::Seal.decrypt(rotated, with: @alice)
  end

  def test_required_padding_checks_policy_id_for_parameterized_policies
    fixed = PQCrypto::Seal.encrypt("fixed", to: @alice.public_key, padding: { to: 12_000 })
    assert_equal "fixed", PQCrypto::Seal.decrypt(
      fixed, with: @alice, required_padding: { to: 12_000 }
    )
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(
        fixed, with: @alice, required_padding: { buckets: [12_000, 24_000] }
      )
    end
  end

  def test_required_padme_rejects_authenticated_noncanonical_envelope
    native = PQCrypto::Seal.const_get(:Native, false)
    payload_id = native.random_bytes(PQCrypto::Seal::Format::PAYLOAD_ID_BYTES)
    nonce = native.random_bytes(PQCrypto::Seal::Format::NONCE_BYTES)
    dek = native.random_bytes(PQCrypto::Seal::Format::DEK_BYTES)
    inner = PQCrypto::Seal::Format.inner_prefix(4, 0) + "data"
    header = PQCrypto::Seal::Format.build_header(
      payload_id: payload_id, payload_nonce: nonce,
      recipient_capacity: 1, slot_size: 2048,
      padded_inner_length: inner.bytesize, public_metadata: "",
      padding_policy_id: PQCrypto::Seal::Format::PADDING_PADME
    )
    section = PQCrypto::Seal.send(
      :build_recipient_section,
      recipients: [@alice.public_key], capacity: 1, slot_size: 2048,
      payload_id: payload_id, header_hash: native.sha256(header), dek: dek,
      wrap_suite_id: PQCrypto::Seal::Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
    )
    ciphertext, tag = native.aegis256_encrypt(dek, nonce, native.sha256(header), inner)
    envelope = header + section + ciphertext + tag

    refute_equal envelope.bytesize, PQCrypto::Seal::Padding.padme_target(envelope.bytesize)
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt(envelope, with: @alice, required_padding: :padme)
    end
  ensure
    PQCrypto::Seal.send(:wipe_string!, dek) if defined?(dek)
    PQCrypto::Seal.send(:wipe_string!, inner) if defined?(inner)
  end

end

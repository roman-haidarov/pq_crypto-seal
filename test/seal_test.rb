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

  def test_wrap_kem_algorithm_is_pinned
    assert_equal :ml_kem_768_x25519_xwing, PQCrypto::Seal::WRAP_KEM_ALGORITHM
    assert_equal 1216, PQCrypto::Seal::Format::XWING_PUBLIC_KEY_BYTES
    assert_equal 1120, PQCrypto::Seal::Format::XWING_CIPHERTEXT_BYTES
    assert_equal 32, PQCrypto::Seal::Format::XWING_SHARED_SECRET_BYTES
  end
end

# frozen_string_literal: true

require_relative 'test_helper'

class SealApiTest < Minitest::Test
  include SealTestSupport

  INTERNAL = %i[unwrap_dek derive_kek build_slot parse_envelope wipe_string! drop_recipient_stanza
                drop_recipient_stanza_file build_recipient_section].freeze
  PUBLIC = %i[credentials encrypt decrypt open inspect_envelope digest rebuild_recipients add_recipient
              rotate_dek encrypt_io decrypt_io encrypt_frame_io decrypt_frame_io encrypt_file decrypt_file
              rebuild_recipients_file add_recipient_file rotate_dek_file inspect_file].freeze

  def test_internal_helpers_are_not_public
    assert_empty(INTERNAL & SEAL.public_methods)
  end

  def test_public_operations_are_exposed
    assert_empty(PUBLIC - SEAL.public_methods)
  end

  def test_wrap_kem_algorithm_is_pinned
    sizes = [FORMAT::XWING_PUBLIC_KEY_BYTES, FORMAT::XWING_CIPHERTEXT_BYTES, FORMAT::XWING_SHARED_SECRET_BYTES]
    assert_equal [:ml_kem_768_x25519_xwing, 1216, 1120, 32], [PQCrypto::Seal::WRAP_KEM_ALGORITHM, *sizes]
  end

  def test_unknown_keyword_is_rejected_like_a_native_keyword
    error = assert_raises(ArgumentError) { SEAL.encrypt('x', to: ALICE.public_key, bogus: 1) }
    assert_equal 'unknown keyword: :bogus', error.message
  end

  def test_missing_keyword_is_rejected_like_a_native_keyword
    error = assert_raises(ArgumentError) { SEAL.rebuild_recipients('', with: ALICE) }
    assert_equal 'missing keyword: :recipients', error.message
  end

  def test_unknown_resource_limit_is_rejected
    assert_raises(ArgumentError) { SEAL.inspect_envelope('', max_bogus_bytes: 1) }
  end

  def test_non_positive_resource_limit_is_rejected
    error = assert_raises(ArgumentError) { SEAL.inspect_envelope('', max_envelope_bytes: 0) }
    assert_equal 'max_envelope_bytes must be positive', error.message
  end

  def test_duplicate_recipients_are_rejected
    assert_raises(PQCrypto::Seal::InvalidConfigurationError) do
      SEAL.encrypt('x', to: [ALICE.public_key] * 2)
    end
  end

  def test_recipients_beyond_capacity_are_rejected
    keys = Array.new(2) { fresh_keypair.public_key }
    assert_raises(PQCrypto::Seal::RecipientCapacityExceeded) { SEAL.encrypt('x', to: keys, recipient_capacity: 1) }
  end

  def test_oversized_private_metadata_is_rejected
    assert_invalid_configuration(metadata: 'm' * (FORMAT::MAX_PRIVATE_METADATA_BYTES + 1))
  end

  def test_preserve_padding_is_only_valid_for_rotation
    assert_invalid_configuration(padding: :preserve)
  end

  def test_invalid_slot_size_is_rejected
    assert_invalid_configuration(slot_size: 3000)
  end

  private

  def assert_invalid_configuration(**options)
    assert_raises(PQCrypto::Seal::InvalidConfigurationError) { SEAL.encrypt('x', to: ALICE.public_key, **options) }
  end
end

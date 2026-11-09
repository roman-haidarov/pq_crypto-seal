# frozen_string_literal: true

require_relative 'test_helper'

class SealRoundTripTest < Minitest::Test
  include SealTestSupport

  DATA = ('image' * 10_000).b.freeze
  SHARED = SEAL.encrypt(DATA, to: [ALICE.public_key, BOB.public_key], metadata: 'private',
                              public_metadata: 'public')
  SECRET = SEAL.encrypt('secret' * 100, to: ALICE.public_key)
  CAPACITY_OFFSET = FORMAT::HEADER_PREFIX_BYTES + 6 + FORMAT::PAYLOAD_ID_BYTES + FORMAT::NONCE_BYTES

  def test_every_recipient_opens_a_multi_recipient_envelope
    assert_equal [DATA, DATA], decrypt_for_each(SHARED)
  end

  def test_open_returns_private_and_public_metadata
    opened = SEAL.open(SHARED, with: BOB)
    assert_equal %w[private public], opened.to_h.values_at(:metadata, :public_metadata)
  end

  def test_public_metadata_conversion_uses_snapshotted_payload_and_recipients
    data = +'original data'
    recipients = [ALICE.public_key]
    calls = 0
    public_metadata = to_str_object do
      calls += 1
      data.replace('edited')
      recipients << BOB.public_key
      'public metadata'
    end

    envelope = SEAL.encrypt(data, to: recipients, recipient_capacity: 1, public_metadata: public_metadata)
    opened = SEAL.open(envelope, with: ALICE)

    assert_equal ['original data', 'public metadata', 1], [opened.data, opened.public_metadata, calls]
  end

  def test_padme_is_the_default_padding_policy
    assert_equal FORMAT::PADDING_PADME, SEAL.open(SHARED, with: ALICE).padding_policy_id
  end

  def test_stranger_cannot_open
    assert_raises(PQCrypto::Seal::RecipientNotFoundError) { SEAL.decrypt(SECRET, with: fresh_keypair) }
  end

  def test_tampered_tag_is_rejected
    broken = flip_byte(SECRET, SECRET.bytesize - 1)
    assert_raises(PQCrypto::Seal::AuthenticationError) { SEAL.decrypt(broken, with: ALICE) }
  end

  def test_tampered_payload_is_rejected
    broken = flip_byte(SECRET, payload_offset(SEAL.inspect_envelope(SECRET)))
    assert_raises(PQCrypto::Seal::AuthenticationError) { SEAL.decrypt(broken, with: ALICE) }
  end

  def test_truncated_envelope_is_rejected
    truncated = SECRET.byteslice(0, SECRET.bytesize - 1)
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt(truncated, with: ALICE) }
  end

  def test_trailing_bytes_are_rejected
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt("#{SECRET}x", with: ALICE) }
  end

  def test_malformed_capacity_is_a_format_error
    broken = SECRET.dup.tap { |copy| copy.setbyte(CAPACITY_OFFSET, 0xff) }
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt(broken, with: ALICE) }
  end

  def test_separately_loaded_credentials_open_envelopes
    credentials = SEAL.credentials(secret_key: ALICE.secret_key, public_key: ALICE.public_key)
    assert_equal DATA, SEAL.decrypt(SHARED, with: credentials)
  end

  def test_array_credentials_open_envelopes
    assert_equal DATA, SEAL.decrypt(SHARED, with: [BOB.secret_key, BOB.public_key])
  end

  def test_resource_limit_rejects_a_large_declared_inner_frame
    assert_raises(PQCrypto::Seal::ResourceLimitError) { SEAL.decrypt(SECRET, with: ALICE, max_staging_bytes: 8) }
  end
end

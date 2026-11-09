# frozen_string_literal: true

require_relative 'test_helper'

class GoldenVectorsTest < Minitest::Test
  include SealTestSupport

  PAYLOAD = ('payload' * 5000).b.freeze
  STREAM_OPTIONS = {
    metadata: 'm', public_metadata: 'p', padding: :none, recipient_capacity: 4, slot_size: 2048
  }.freeze

  def test_header_prefix_bytes_are_frozen
    envelope = header_envelope
    header_length = FORMAT.parse_header(envelope).raw.bytesize
    assert_equal [FORMAT::MAGIC, 1, header_length, 1, 1, 0, FORMAT::PADDING_NONE], envelope.unpack('a8CNnCnC')
  end

  def test_parsed_header_reports_the_requested_fields
    header = FORMAT.parse_header(header_envelope)
    fields = header.to_h.values_at(:public_metadata, :padding_policy_id, :recipient_capacity, :slot_size)
    assert_equal ['meta', FORMAT::PADDING_NONE, 4, 2048], fields
  end

  def test_payload_is_authenticated_with_the_header_hash
    envelope = SEAL.encrypt('data', to: ALICE.public_key, padding: :none)
    associated_data = native.sha256(FORMAT.parse_header(envelope).raw)
    assert_equal 'data', FORMAT::InnerCodec.parse(open_payload(envelope, associated_data)).content
  end

  def test_one_shot_and_streaming_encryption_share_header_and_payload
    envelopes = %i[seal_encrypt stream_encrypt].map { |name| seeded(name) }
    assert_equal(*envelopes.map { |envelope| without_section(envelope) })
  end

  def test_streamed_envelope_decrypts
    streamed = stream_encrypt(PAYLOAD, ALICE.public_key, STREAM_OPTIONS)
    assert_equal PAYLOAD, SEAL.decrypt(streamed, with: ALICE)
  end

  def test_multi_recipient_envelope_opens_for_every_recipient
    envelope = with_random(0x1122_3344_5566_7788) do
      SEAL.encrypt('shared-doc', to: [ALICE.public_key, BOB.public_key], metadata: 'private', padding: :padme)
    end
    assert_equal %w[shared-doc shared-doc], decrypt_for_each(envelope)
  end

  def test_padme_policy_id_is_recorded
    envelope = SEAL.encrypt('shared-doc', to: ALICE.public_key, padding: :padme)
    assert_equal FORMAT::PADDING_PADME, SEAL.inspect_envelope(envelope).padding_policy_id
  end

  def test_padme_envelope_size_is_canonical
    size = SEAL.encrypt('shared-doc', to: ALICE.public_key, padding: :padme).bytesize
    assert_equal size, PQCrypto::Seal::Padding.padme_target(size)
  end

  private

  def header_envelope
    with_random(0x0102_0304_0506_0708) do
      SEAL.encrypt('golden', to: ALICE.public_key, public_metadata: 'meta', padding: :none,
                             recipient_capacity: 4, slot_size: 2048)
    end
  end

  def seeded(name)
    with_random(0xAABB_CCDD_EEFF_0011) { __send__(name, PAYLOAD, ALICE.public_key, STREAM_OPTIONS) }
  end
end

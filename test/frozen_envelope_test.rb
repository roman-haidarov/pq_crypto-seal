# frozen_string_literal: true

require_relative 'test_helper'

class FrozenEnvelopeTest < Minitest::Test
  include SealTestSupport

  DATA = ("frozen-envelope\0" * 300).b.freeze
  SHA256 = 'b96c70f6086d380b1f7ea5f2dfb1c91f2a120a25f9708a16e8feecf8d2e72fdf'
  OPTIONS = {
    metadata: 'private', public_metadata: 'public', recipient_capacity: 1, slot_size: 2048, padding: :padme
  }.freeze
  VECTOR = SealTestSupport.fixture('xwing-draft-10-vector-1.json').freeze

  def test_frozen_envelope_digest_is_stable
    assert_equal SHA256, native.sha256(frozen_envelope { |key| SEAL.encrypt(DATA, to: key, **OPTIONS) }).unpack1('H*')
  end

  def test_streaming_reproduces_the_frozen_envelope
    streamed = frozen_envelope { |key| stream_encrypt(DATA, key, OPTIONS.merge(chunk_size: 37)) }
    assert_equal SHA256, native.sha256(streamed).unpack1('H*')
  end

  def test_frozen_envelope_opens_with_the_vector_secret_key
    envelope = frozen_envelope { |key| SEAL.encrypt(DATA, to: key, **OPTIONS) }
    assert_equal DATA, SEAL.decrypt(envelope, with: vector_keypair(VECTOR), required_padding: :padme)
  end

  private

  def frozen_envelope
    public_key = stubbed_key
    with_random(0x0123_4567_89AB_CDEF) { yield public_key }
  end

  def stubbed_key
    encapsulation = PQCrypto::HybridKEM::EncapsulationResult.new(hex(VECTOR.fetch('ct')), hex(VECTOR.fetch('ss')))
    public_key = vector_public_key(VECTOR)
    public_key.define_singleton_method(:encapsulate) { encapsulation }
    public_key
  end
end

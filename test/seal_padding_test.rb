# frozen_string_literal: true

require_relative 'test_helper'

class SealPaddingTest < Minitest::Test
  include SealTestSupport

  PADME = SEAL.encrypt('pad-default', to: ALICE.public_key, padding: :padme)
  NONE = SEAL.encrypt('none-default', to: ALICE.public_key, padding: :none)
  FIXED = SEAL.encrypt('fixed-default', to: ALICE.public_key, padding: { to: 12_000 })
  BUCKETS = [8_000, 16_000, 32_000].freeze
  BUCKETED = SEAL.encrypt('bucketed', to: ALICE.public_key, padding: { buckets: BUCKETS })

  def test_none_policy_id_is_recorded
    assert_equal FORMAT::PADDING_NONE, SEAL.inspect_envelope(NONE).padding_policy_id
  end

  def test_default_requirement_accepts_every_policy
    opened = [PADME, NONE, FIXED, BUCKETED].map { |envelope| SEAL.decrypt(envelope, with: ALICE) }
    assert_equal %w[pad-default none-default fixed-default bucketed], opened
  end

  def test_requirement_can_be_disabled
    assert_equal 'pad-default', SEAL.decrypt(PADME, with: ALICE, required_padding: false)
  end

  def test_fixed_padding_produces_the_exact_size
    assert_equal [12_000, FORMAT::PADDING_FIXED], [FIXED.bytesize, SEAL.inspect_envelope(FIXED).padding_policy_id]
  end

  def test_fixed_requirement_accepts_a_matching_envelope
    assert_equal 'fixed-default', SEAL.decrypt(FIXED, with: ALICE, required_padding: { to: 12_000 })
  end

  def test_fixed_requirement_rejects_another_target
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt(FIXED, with: ALICE, required_padding: { to: 24_000 }) }
  end

  def test_bucket_padding_picks_a_configured_bucket
    assert_includes BUCKETS, BUCKETED.bytesize
  end

  def test_bucket_requirement_accepts_a_bucketed_envelope
    assert_equal 'bucketed', SEAL.decrypt(BUCKETED, with: ALICE, required_padding: { buckets: BUCKETS })
  end

  def test_parameterized_requirement_checks_the_policy_id
    assert_raises(PQCrypto::Seal::FormatError) do
      SEAL.decrypt(FIXED, with: ALICE, required_padding: { buckets: [12_000, 24_000] })
    end
  end

  def test_padme_requirement_accepts_an_honest_envelope
    assert_equal 'pad-default', SEAL.decrypt(PADME, with: ALICE, required_padding: :padme)
  end

  def test_none_requirement_rejects_a_padme_envelope
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt(PADME, with: ALICE, required_padding: :none) }
  end

  def test_none_requirement_accepts_an_unpadded_envelope
    assert_equal 'none-default', SEAL.decrypt(NONE, with: ALICE, required_padding: :none)
  end

  def test_padme_requirement_rejects_an_authenticated_noncanonical_envelope
    envelope = noncanonical_padme_envelope
    size = envelope.bytesize
    refute_equal size, PQCrypto::Seal::Padding.padme_target(size)
    assert_raises(PQCrypto::Seal::FormatError) { SEAL.decrypt(envelope, with: ALICE, required_padding: :padme) }
  end
end

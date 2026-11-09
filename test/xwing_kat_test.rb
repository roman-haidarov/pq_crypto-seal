# frozen_string_literal: true

require_relative 'test_helper'

class XWingKatTest < Minitest::Test
  include SealTestSupport

  def test_first_vector_decapsulates_to_the_published_secret
    assert_decapsulates fixture('xwing-draft-10-vector-1.json')
  end

  def test_second_vector_decapsulates_to_the_published_secret
    assert_decapsulates fixture('xwing-draft-10-vector-2.json')
  end

  def test_vector_sizes_match_wrap_suite_one
    vector = fixture('xwing-draft-10-vector-1.json')
    sizes = %w[pk sk ct ss].map { |name| hex(vector.fetch(name)).bytesize }
    assert_equal [FORMAT::XWING_PUBLIC_KEY_BYTES, 32, FORMAT::XWING_CIPHERTEXT_BYTES, 32], sizes
  end

  private

  def assert_decapsulates(vector)
    secret_key = PQCrypto::HybridKEM.secret_key_from_bytes(ALGORITHM, hex(vector.fetch('sk')))
    assert_equal hex(vector.fetch('ss')), secret_key.decapsulate(hex(vector.fetch('ct')))
  ensure
    secret_key&.wipe!
  end
end

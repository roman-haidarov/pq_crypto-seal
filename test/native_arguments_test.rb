# frozen_string_literal: true

require_relative 'test_helper'

class NativeArgumentsTest < Minitest::Test
  include SealTestSupport

  KEY = ('k' * 32).freeze
  NONCE = ('n' * 32).freeze

  def test_to_str_arguments_are_converted_before_use
    key = to_str_object { KEY }
    assert_equal native.aegis256_encrypt(KEY, NONCE, '', 'm'), native.aegis256_encrypt(key, NONCE, '', 'm')
  end

  def test_to_str_cannot_shrink_an_already_converted_key
    key = +KEY
    nonce = to_str_object { key.replace('x') && NONCE }
    assert_raises(ArgumentError) { native.aegis256_encrypt(key, nonce, '', 'm') }
  end

  def test_authentication_error_class_survives_heap_compaction
    skip 'heap compaction is unavailable' unless defined?(GC.compact)

    compact_heap
    assert_raises(PQCrypto::Seal::AuthenticationError) { native.aegis256_decrypt(KEY, NONCE, '', 'abc', 't' * 32) }
  end

  def test_encryption_returns_strings_under_gc_stress
    original_stress = GC.stress
    ['', 'x' * 32_768].each do |message|
      begin
        GC.stress = true
        ciphertext, tag = native.aegis256_encrypt(KEY, NONCE, '', message)
      ensure
        GC.stress = original_stress
      end
      assert_instance_of String, ciphertext
      assert_equal message, native.aegis256_decrypt(KEY, NONCE, '', ciphertext, tag)
    end
  end

  def test_wipe_overwrites_a_mutable_string_in_place
    secret = +'secret-bytes'
    assert native.wipe(secret)
    assert_equal "\0" * 12, secret
  end

  def test_wipe_skips_frozen_and_non_string_values
    refute native.wipe('frozen')
    refute native.wipe(nil)
  end

  def test_hkdf_rejects_empty_output
    assert_raises(ArgumentError) { native.hkdf_sha256('ikm', '', 0) }
  end

  def test_hkdf_rejects_output_longer_than_255_blocks
    assert_raises(ArgumentError) { native.hkdf_sha256('ikm', '', 8161) }
  end

  def test_hkdf_accepts_the_maximum_output_length
    assert_equal 8160, native.hkdf_sha256('ikm', '', 8160).bytesize
  end

  def test_random_bytes_rejects_negative_lengths
    assert_raises(ArgumentError) { native.random_bytes(-1) }
  end
end

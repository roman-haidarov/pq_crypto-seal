# frozen_string_literal: true

require_relative 'test_helper'

class NativeTest < Minitest::Test
  include SealTestSupport

  KEY = ('k' * 32).freeze
  NONCE = ('n' * 32).freeze
  MESSAGE = ('abc123' * 20_000).b.freeze
  LARGE = ('x' * (4 * 1024 * 1024)).freeze

  def test_incremental_encryption_matches_one_shot
    expected = native.aegis256_encrypt(KEY, NONCE, 'header', MESSAGE)
    encryptor = native::Encryptor.new(KEY, NONCE, 'header')
    streamed = chunks(MESSAGE, 7777).map { |chunk| encryptor.update(chunk) }.join
    assert_equal expected, [streamed, encryptor.final]
  end

  def test_incremental_decryption_restores_message
    ciphertext, tag = native.aegis256_encrypt(KEY, NONCE, 'header', MESSAGE)
    decryptor = native::Decryptor.new(KEY, NONCE, 'header')
    plaintext = chunks(ciphertext, 3333).map { |chunk| decryptor.update(chunk) }.join
    assert_equal [MESSAGE, true], [plaintext, decryptor.final(tag)]
  end

  def test_tampered_tag_fails_authentication
    ciphertext, tag = native.aegis256_encrypt(KEY, NONCE, '', 'secret')
    assert_raises(PQCrypto::Seal::AuthenticationError) do
      native.aegis256_decrypt(KEY, NONCE, '', ciphertext, flip_byte(tag, 0))
    end
  end

  def test_concurrent_updates_on_one_state_are_rejected
    encryptor = native::Encryptor.new(KEY, NONCE, 'ad')
    assert_equal %i[busy updated], concurrent_outcomes(encryptor, LARGE)
  end

  def test_streaming_state_cannot_be_copied
    encryptor = native::Encryptor.new(KEY, NONCE, '')
    assert_raises(TypeError) { encryptor.dup }
  end

  def test_finalized_state_rejects_updates
    encryptor = native::Encryptor.new(KEY, NONCE, '')
    encryptor.final
    error = assert_raises(RuntimeError) { encryptor.update('more') }
    assert_equal 'AEGIS state is finalized', error.message
  end

  def test_uninitialized_state_rejects_updates
    error = assert_raises(RuntimeError) { native::Decryptor.allocate.update('data') }
    assert_equal 'AEGIS state is not initialized', error.message
  end
end

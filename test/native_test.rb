# frozen_string_literal: true
require_relative "test_helper"

class NativeTest < Minitest::Test
  def native
    PQCrypto::Seal.const_get(:Native, false)
  end

  def test_aegis_one_shot_and_incremental_are_identical
    key = "k" * 32
    nonce = "n" * 32
    ad = "header"
    message = ("abc123" * 20_000).b
    ciphertext, tag = native.aegis256_encrypt(key, nonce, ad, message)

    enc = native::Encryptor.new(key, nonce, ad)
    streamed = message.bytes.each_slice(7777).map { |slice| enc.update(slice.pack("C*")) }.join
    assert_equal ciphertext, streamed
    assert_equal tag, enc.final

    dec = native::Decryptor.new(key, nonce, ad)
    plain = streamed.bytes.each_slice(3333).map { |slice| dec.update(slice.pack("C*")) }.join
    assert dec.final(tag)
    assert_equal message, plain
  end

  def test_tampered_tag_fails
    key = "k" * 32
    nonce = "n" * 32
    ciphertext, tag = native.aegis256_encrypt(key, nonce, "", "secret")
    tag.setbyte(0, tag.getbyte(0) ^ 1)
    assert_raises(PQCrypto::Seal::AuthenticationError) do
      native.aegis256_decrypt(key, nonce, "", ciphertext, tag)
    end
  end
end

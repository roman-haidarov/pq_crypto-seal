# frozen_string_literal: true

require_relative 'test_helper'

class AegisVectorsTest < Minitest::Test
  include SealTestSupport

  KEY = SealTestSupport.hex('1001000000000000000000000000000000000000000000000000000000000000')
  NONCE = SealTestSupport.hex('1000020000000000000000000000000000000000000000000000000000000000')
  POSITIVE = [
    ['', '00000000000000000000000000000000', '754fc3d8c973246dcc6d741412a4b236',
     '1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13'],
    ['', '', '', '6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a'],
    ['0001020304050607', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
     'f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711',
     'b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a'],
    ['0001020304050607', '000102030405060708090a0b0c0d', 'f373079ed84b2709faee37358458',
     '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9'],
    ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829',
     '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637',
     '57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67',
     'a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734']
  ].map { |vector| vector.map { |value| SealTestSupport.hex(value) }.freeze }.freeze
  NEGATIVE = [
    %w[1000020000000000000000000000000000000000000000000000000000000000
       1001000000000000000000000000000000000000000000000000000000000000
       0001020304050607 f373079ed84b2709faee37358458
       8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9],
    %w[1001000000000000000000000000000000000000000000000000000000000000
       1000020000000000000000000000000000000000000000000000000000000000
       0001020304050607 f373079ed84b2709faee37358459
       8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9],
    %w[1001000000000000000000000000000000000000000000000000000000000000
       1000020000000000000000000000000000000000000000000000000000000000
       0001020304050608 f373079ed84b2709faee37358458
       8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9],
    %w[1001000000000000000000000000000000000000000000000000000000000000
       1000020000000000000000000000000000000000000000000000000000000000
       0001020304050607 f373079ed84b2709faee37358458
       8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da]
  ].map { |vector| vector.map { |value| SealTestSupport.hex(value) }.freeze }.freeze

  def test_draft18_vectors_encrypt_to_the_published_output
    assert_empty(POSITIVE.reject { |vector| encrypts_to_vector?(vector) })
  end

  def test_draft18_vectors_decrypt_to_the_message
    assert_empty(POSITIVE.reject { |vector| decrypts_to_vector?(vector) })
  end

  def test_draft18_negative_vectors_fail_authentication
    assert_empty(NEGATIVE.reject { |arguments| authentication_fails?(arguments) })
  end

  def test_rfc5869_empty_salt_vector
    expected = hex('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8')
    assert_equal expected, native.hkdf_sha256(hex('0b' * 22), ''.b, 42)
  end

  private

  def encrypts_to_vector?(vector)
    associated_data, message, ciphertext, tag = vector
    native.aegis256_encrypt(KEY, NONCE, associated_data, message) == [ciphertext, tag]
  end

  def decrypts_to_vector?(vector)
    associated_data, message, ciphertext, tag = vector
    native.aegis256_decrypt(KEY, NONCE, associated_data, ciphertext, tag) == message
  end

  def authentication_fails?(arguments)
    native.aegis256_decrypt(*arguments)
    false
  rescue PQCrypto::Seal::AuthenticationError
    true
  end
end

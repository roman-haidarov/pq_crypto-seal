# frozen_string_literal: true
require_relative "test_helper"

class AegisVectorsTest < Minitest::Test
  def native
    PQCrypto::Seal.const_get(:Native, false)
  end

  KEY = ["1001000000000000000000000000000000000000000000000000000000000000"].pack("H*")
  NONCE = ["1000020000000000000000000000000000000000000000000000000000000000"].pack("H*")

  POSITIVE = [
    ["", "00000000000000000000000000000000", "754fc3d8c973246dcc6d741412a4b236", "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"],
    ["", "", "", "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"],
    ["0001020304050607", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711", "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"],
    ["0001020304050607", "000102030405060708090a0b0c0d", "f373079ed84b2709faee37358458", "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"],
    ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829", "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637", "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67", "a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"]
  ].freeze

  def test_draft_18_positive_vectors
    POSITIVE.each do |ad_hex, msg_hex, ct_hex, tag_hex|
      ad, msg, expected_ct, expected_tag = [ad_hex, msg_hex, ct_hex, tag_hex].map { |hex| [hex].pack("H*") }
      ct, tag = native.aegis256_encrypt(KEY, NONCE, ad, msg)
      assert_equal expected_ct, ct
      assert_equal expected_tag, tag
      assert_equal msg, native.aegis256_decrypt(KEY, NONCE, ad, ct, tag)
    end
  end

  def test_draft_18_negative_vectors
    valid_ct = ["f373079ed84b2709faee37358458"].pack("H*")
    valid_tag = ["8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"].pack("H*")
    ad = ["0001020304050607"].pack("H*")

    cases = [
      [["1000020000000000000000000000000000000000000000000000000000000000"].pack("H*"), ["1001000000000000000000000000000000000000000000000000000000000000"].pack("H*"), ad, valid_ct, valid_tag],
      [KEY, NONCE, ad, ["f373079ed84b2709faee37358459"].pack("H*"), valid_tag],
      [KEY, NONCE, ["0001020304050608"].pack("H*"), valid_ct, valid_tag],
      [KEY, NONCE, ad, valid_ct, ["8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da"].pack("H*")]
    ]

    cases.each do |key, nonce, case_ad, ct, tag|
      assert_raises(PQCrypto::Seal::AuthenticationError) do
        native.aegis256_decrypt(key, nonce, case_ad, ct, tag)
      end
    end
  end

  def test_rfc5869_empty_salt_vector
    ikm = ["0b" * 22].pack("H*")
    expected = ["8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"].pack("H*")
    assert_equal expected, native.hkdf_sha256(ikm, "".b, 42)
  end
end

# frozen_string_literal: true

require "json"
require_relative "test_helper"

class XWingKatTest < Minitest::Test
  ALGORITHM = :ml_kem_768_x25519_xwing

  def test_draft_10_decapsulation_vectors
    [1, 2].each do |number|
      vector = load_vector(number)
      keypair = keypair_from(vector)
      ciphertext = decode(vector.fetch("ct"))
      expected = decode(vector.fetch("ss"))

      assert_equal 1216, keypair.public_key.to_bytes.bytesize
      assert_equal 32, keypair.secret_key.to_bytes.bytesize
      assert_equal 1120, ciphertext.bytesize
      assert_equal 32, expected.bytesize
      assert_equal expected, keypair.secret_key.decapsulate(ciphertext)
    ensure
      keypair.secret_key.wipe! if keypair
    end
  end

  private

  def load_vector(number)
    path = File.expand_path("fixtures/xwing-draft-10-vector-#{number}.json", __dir__)
    JSON.parse(File.read(path))
  end

  def keypair_from(vector)
    public_key = PQCrypto::HybridKEM.public_key_from_bytes(ALGORITHM, decode(vector.fetch("pk")))
    secret_key = PQCrypto::HybridKEM.secret_key_from_bytes(ALGORITHM, decode(vector.fetch("sk")))
    PQCrypto::HybridKEM::Keypair.new(public_key, secret_key)
  end

  def decode(hex)
    [hex].pack("H*")
  end
end

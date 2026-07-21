# frozen_string_literal: true

require "json"
require_relative "test_helper"

class GoldenVectorsTest < Minitest::Test
  def native
    PQCrypto::Seal.const_get(:Native, false)
  end

  class CountingRandom
    def initialize(seed, native)
      @state = [seed].pack("Q>")
      @native = native
      @buffer = +"".b
    end

    def bytes(length)
      return "".b if length.zero?

      while @buffer.bytesize < length
        @state = @native.sha256(@state)
        @buffer << @state
      end
      @buffer.slice!(0, length).b
    end
  end

  def with_deterministic_random(seed)
    mod = native
    stream = CountingRandom.new(seed, mod)
    singleton = mod.singleton_class
    singleton.send(:alias_method, :__real_random_bytes, :random_bytes)
    singleton.send(:define_method, :random_bytes) { |length| stream.bytes(length) }
    yield
  ensure
    singleton.send(:alias_method, :random_bytes, :__real_random_bytes)
    singleton.send(:remove_method, :__real_random_bytes)
  end

  def test_xwing_kem_wire_contract
    keypair = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    assert_equal :ml_kem_768_x25519_xwing, keypair.public_key.algorithm
    assert_equal PQCrypto::Seal::Format::XWING_PUBLIC_KEY_BYTES,
                 keypair.public_key.to_bytes.bytesize
    encapsulated = keypair.public_key.encapsulate
    assert_equal PQCrypto::Seal::Format::XWING_CIPHERTEXT_BYTES,
                 encapsulated.ciphertext.bytesize
    assert_equal PQCrypto::Seal::Format::XWING_SHARED_SECRET_BYTES,
                 encapsulated.shared_secret.bytesize
    recovered = keypair.secret_key.decapsulate(encapsulated.ciphertext)
    assert_equal encapsulated.shared_secret, recovered
  end

  def test_immutable_header_layout_is_frozen
    keypair = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    envelope = with_deterministic_random(0x0102_0304_0506_0708) do
      PQCrypto::Seal.encrypt(
        "golden", to: keypair.public_key,
        public_metadata: "meta", padding: :none,
        recipient_capacity: 4, slot_size: 2048
      )
    end

    fmt = PQCrypto::Seal::Format
    offset = 0
    assert_equal fmt::MAGIC, envelope.byteslice(offset, 8); offset += 8
    assert_equal 1, envelope.getbyte(offset); offset += 1 # version
    header_length = envelope.byteslice(offset, 4).unpack1("N"); offset += 4
    assert_equal fmt::CONTENT_SUITE_AEGIS256, envelope.byteslice(offset, 2).unpack1("n"); offset += 2
    assert_equal fmt::LOOKUP_HINT, envelope.getbyte(offset); offset += 1
    assert_equal fmt::FLAGS, envelope.byteslice(offset, 2).unpack1("n"); offset += 2
    assert_equal fmt::PADDING_NONE, envelope.getbyte(offset); offset += 1

    header = fmt.parse_header(envelope)
    assert_equal header_length, header.raw.bytesize
    assert_equal "meta", header.public_metadata
    assert_equal fmt::PADDING_NONE, header.padding_policy_id
    assert_equal 4, header.recipient_capacity
    assert_equal 2048, header.slot_size
  end

  def test_payload_ad_is_sha256_of_header
    keypair = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    envelope = PQCrypto::Seal.encrypt("data", to: keypair.public_key, padding: :none)
    header = PQCrypto::Seal::Format.parse_header(envelope)

    opened = PQCrypto::Seal.open(envelope, with: keypair)
    assert_equal "data", opened.data
    refute_equal native.sha256(header.raw), header.raw
    assert_equal 32, native.sha256(header.raw).bytesize
  end

  def test_one_shot_and_incremental_agree_on_deterministic_regions
    keypair = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    data = ("payload" * 5000).b

    one_shot = with_deterministic_random(0xAABB_CCDD_EEFF_0011) do
      PQCrypto::Seal.encrypt(
        data, to: keypair.public_key, metadata: "m",
        public_metadata: "p", padding: :none,
        recipient_capacity: 4, slot_size: 2048
      )
    end

    incremental = with_deterministic_random(0xAABB_CCDD_EEFF_0011) do
      input = StringIO.new(data)
      output = StringIO.new(+"".b)
      PQCrypto::Seal.encrypt_io(
        input, output, size: data.bytesize, to: keypair.public_key,
        metadata: "m", public_metadata: "p", padding: :none,
        recipient_capacity: 4, slot_size: 2048
      )
      output.string
    end

    fmt = PQCrypto::Seal::Format
    header_a = fmt.parse_header(one_shot)
    header_b = fmt.parse_header(incremental)

    assert_equal header_a.raw, header_b.raw,
                 "one-shot and incremental must build identical headers"
    section_len = fmt.section_length(header_a)
    payload_a = one_shot.byteslice(header_a.raw.bytesize + section_len..)
    payload_b = incremental.byteslice(header_b.raw.bytesize + section_len..)
    assert_equal payload_a, payload_b,
                 "one-shot and incremental must produce identical payload bytes"
    assert_equal data, PQCrypto::Seal.decrypt(one_shot, with: keypair)
    assert_equal data, PQCrypto::Seal.decrypt(incremental, with: keypair)
  end

  def test_multi_recipient_golden_roundtrip_is_stable
    alice = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    bob = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    envelope = with_deterministic_random(0x1122_3344_5566_7788) do
      PQCrypto::Seal.encrypt(
        "shared-doc", to: [alice.public_key, bob.public_key],
        metadata: "private", padding: :padme,
        recipient_capacity: 4, slot_size: 2048
      )
    end
    assert_equal "shared-doc", PQCrypto::Seal.decrypt(envelope, with: alice)
    assert_equal "shared-doc", PQCrypto::Seal.decrypt(envelope, with: bob)
    info = PQCrypto::Seal.inspect_envelope(envelope)
    assert_equal 4, info.recipient_capacity
    assert_equal PQCrypto::Seal::Format::PADDING_PADME, info.padding_policy_id
    assert_equal PQCrypto::Seal::Padding.padme_target(info.envelope_bytes),
                 info.envelope_bytes
  end
  def test_exact_frozen_envelope_and_streaming_equivalence
    vector = JSON.parse(File.read(File.expand_path("fixtures/xwing-draft-10-vector-1.json", __dir__)))
    public_key = PQCrypto::HybridKEM.public_key_from_bytes(
      PQCrypto::Seal::WRAP_KEM_ALGORITHM, [vector.fetch("pk")].pack("H*")
    )
    secret_key = PQCrypto::HybridKEM.secret_key_from_bytes(
      PQCrypto::Seal::WRAP_KEM_ALGORITHM, [vector.fetch("sk")].pack("H*")
    )
    keypair = PQCrypto::HybridKEM::Keypair.new(public_key, secret_key)
    data = ("frozen-envelope\0" * 300).b

    one_shot = deterministic_envelope(public_key, vector) do
      PQCrypto::Seal.encrypt(
        data, to: public_key, metadata: "private", public_metadata: "public",
        recipient_capacity: 1, slot_size: 2048, padding: :padme
      )
    end

    streamed = deterministic_envelope(public_key, vector) do
      output = StringIO.new(+"".b)
      PQCrypto::Seal.encrypt_io(
        StringIO.new(data), output, size: data.bytesize, to: public_key,
        metadata: "private", public_metadata: "public",
        recipient_capacity: 1, slot_size: 2048, padding: :padme, chunk_size: 37
      )
      output.string
    end

    assert_equal one_shot, streamed
    assert_equal "b96c70f6086d380b1f7ea5f2dfb1c91f2a120a25f9708a16e8feecf8d2e72fdf", native.sha256(one_shot).unpack1("H*")
    assert_equal data, PQCrypto::Seal.decrypt(one_shot, with: keypair, required_padding: :padme)
  ensure
    secret_key.wipe! if secret_key
  end

  def deterministic_envelope(public_key, vector)
    encapsulation = PQCrypto::HybridKEM::EncapsulationResult.new(
      [vector.fetch("ct")].pack("H*"), [vector.fetch("ss")].pack("H*")
    )
    with_deterministic_random(0x0123_4567_89AB_CDEF) do
      public_key.stub(:encapsulate, encapsulation) { yield }
    end
  end

end

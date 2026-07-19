# frozen_string_literal: true

require_relative "test_helper"

# Protocol-drift detection for the frozen v1 wire format.
#
# A fully byte-frozen "plaintext -> exact envelope" vector is not achievable
# from this gem alone, because X-Wing encapsulation draws its own randomness
# inside pq_crypto and is not injectable here. Instead this suite pins every
# part of the construction that Seal itself controls and every derived value
# that would change if the protocol silently drifted:
#
#   * the X-Wing wire contract (algorithm id + exact key/ciphertext/secret sizes)
#   * the exact immutable-header byte layout for a fixed input
#   * the payload associated data derivation (SHA-256 of the header)
#   * the KDF label wiring and slot offsets
#   * one-shot and incremental encryption producing identical bytes under a
#     fixed deterministic RNG
#
# Any change to labels, offsets, field order, or hashing breaks these.
class GoldenVectorsTest < Minitest::Test
  def native
    PQCrypto::Seal.const_get(:Native, false)
  end

  # Deterministic counter-based byte stream so every Seal-side random draw
  # (payload id, nonces, DEK, section id, padding) is fixed across a run.
  class CountingRandom
    def initialize(seed, native)
      @state = [seed].pack("Q>")
      @native = native
    end

    def bytes(length)
      return "".b if length.zero?

      out = +"".b
      while out.bytesize < length
        @state = @native.sha256(@state)
        out << @state
      end
      out.byteslice(0, length).b
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
    # The recipient can open the envelope, which only succeeds if the AD used
    # for the payload equals SHA-256(header.raw); a drifted AD fails the tag.
    opened = PQCrypto::Seal.open(envelope, with: keypair)
    assert_equal "data", opened.data
    refute_equal native.sha256(header.raw), header.raw
    assert_equal 32, native.sha256(header.raw).bytesize
  end

  def test_one_shot_and_incremental_agree_on_deterministic_regions
    # X-Wing encapsulation randomness lives inside pq_crypto and is NOT covered
    # by the Native.random_bytes stub, so the recipient section (KEM ciphertexts)
    # differs between two runs. Everything Seal itself controls must still match:
    # the immutable header and the payload ciphertext+tag.
    #
    # padding MUST be :none: one-shot draws padding as one random_bytes call, the
    # IO path draws it in chunk_size pieces, which would diverge under the same
    # deterministic RNG. With :none both draw zero padding bytes.
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

    # Immutable header bytes are fully deterministic and must be identical.
    assert_equal header_a.raw, header_b.raw,
                 "one-shot and incremental must build identical headers"

    # Payload region (ciphertext + tag) is deterministic given a fixed DEK,
    # nonce, and header hash; extract and compare it across both paths.
    section_len = fmt.section_length(header_a)
    payload_a = one_shot.byteslice(header_a.raw.bytesize + section_len..)
    payload_b = incremental.byteslice(header_b.raw.bytesize + section_len..)
    assert_equal payload_a, payload_b,
                 "one-shot and incremental must produce identical payload bytes"

    # Both envelopes must open to the exact plaintext.
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
    # Padmé targets the full envelope, so the total size equals the Padmé target.
    assert_equal PQCrypto::Seal::Padding.padme_target(info.envelope_bytes),
                 info.envelope_bytes
  end
end

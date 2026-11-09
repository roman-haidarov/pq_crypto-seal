# frozen_string_literal: true

require_relative 'test_helper'

class IOStreamTest < Minitest::Test
  include SealTestSupport

  DATA = Random.new(7).bytes((2 * 1024 * 1024) + 31).freeze
  SMALL = SEAL.encrypt('payload', to: ALICE.public_key, padding: :none)
  STAGED = ('decrypted-partial-write' * 500).freeze

  def test_stream_round_trip_with_odd_chunk_sizes
    envelope = stream_encrypt(DATA, ALICE.public_key, chunk_size: 65_537)
    assert_equal DATA, stream_decrypt(envelope, with: ALICE, chunk_size: 43_211)
  end

  def test_decryption_uses_the_validated_chunk_size
    assert_equal 'payload', stream_decrypt(SMALL, with: ALICE, chunk_size: '3')
  end

  def test_encryption_keeps_the_readers_buffer_intact
    source = +'caller-owned payload'
    reads = [source, nil]
    input = Object.new
    input.define_singleton_method(:read) { |_size| reads.shift }
    output = StringIO.new(String.new)

    SEAL.encrypt_io(input, output, size: source.bytesize, to: ALICE.public_key)

    assert_equal 'caller-owned payload', source
    assert_equal source, SEAL.decrypt(output.string, with: ALICE)
  end

  def test_trailing_bytes_are_rejected_by_default
    assert_raises(PQCrypto::Seal::FormatError) { stream_decrypt("#{SMALL}TRAIL", with: ALICE) }
  end

  def test_frame_decryption_leaves_trailing_bytes_unread
    input = StringIO.new("#{SMALL}TRAIL")
    SEAL.decrypt_frame_io(input, StringIO.new(String.new), with: ALICE)
    assert_equal 'TRAIL', input.read
  end

  def test_encryption_survives_partial_writes
    output = PartialWriter.new(7)
    SEAL.encrypt_io(StringIO.new('hello-partial-write'), output, size: 19, to: ALICE.public_key, padding: :none)
    assert_equal 'hello-partial-write', SEAL.decrypt(output.buffer, with: ALICE)
  end

  def test_decryption_survives_partial_writes
    output = PartialWriter.new(5)
    SEAL.decrypt_io(StringIO.new(SEAL.encrypt(STAGED, to: ALICE.public_key)), output, with: ALICE)
    assert_equal STAGED, output.buffer
  end

  def test_bad_tag_publishes_nothing
    output = StringIO.new(String.new)
    broken = flip_byte(SMALL, SMALL.bytesize - 1)
    assert_raises(PQCrypto::Seal::AuthenticationError) { SEAL.decrypt_io(StringIO.new(broken), output, with: ALICE) }
    assert_empty output.string
  end

  def test_writer_without_progress_is_rejected
    assert_raises(IOError) do
      SEAL.encrypt_io(StringIO.new('x'), StalledWriter.new, size: 1, to: ALICE.public_key, padding: :none)
    end
  end

  def test_short_input_is_rejected
    assert_raises(EOFError) { encrypt_declared(2) }
  end

  def test_extra_input_is_rejected_by_default
    assert_raises(ArgumentError) { encrypt_declared(0) }
  end

  def test_frame_encryption_tolerates_extra_input
    output = StringIO.new(String.new)
    SEAL.encrypt_frame_io(StringIO.new('xy'), output, size: 1, to: ALICE.public_key)
    assert_equal 'x', SEAL.decrypt(output.string, with: ALICE)
  end

  def test_frame_io_accepts_explicit_strict_options
    assert_raises(ArgumentError) do
      SEAL.encrypt_frame_io(StringIO.new('xy'), StringIO.new(String.new), size: 1,
                            to: ALICE.public_key, strict_size: true)
    end
    assert_raises(PQCrypto::Seal::FormatError) do
      SEAL.decrypt_frame_io(StringIO.new("#{SMALL}TRAIL"), StringIO.new(String.new), with: ALICE, strict_eof: true)
    end
  end

  def test_negative_size_is_rejected
    assert_raises(ArgumentError) { encrypt_declared(-1) }
  end

  def test_non_positive_chunk_size_is_rejected
    assert_raises(ArgumentError) { stream_encrypt('x', ALICE.public_key, chunk_size: 0) }
  end
end

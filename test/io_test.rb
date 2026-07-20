# frozen_string_literal: true
require_relative "test_helper"

class IOTest < Minitest::Test
  def setup
    @keypair = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
  end

  def test_io_round_trip
    data = Random.new(7).bytes(2 * 1024 * 1024 + 31)
    encrypted = StringIO.new("".b)
    PQCrypto::Seal.encrypt_io(StringIO.new(data), encrypted, size: data.bytesize,
                              to: @keypair.public_key, chunk_size: 65_537)
    encrypted.rewind
    output = StringIO.new("".b)
    PQCrypto::Seal.decrypt_io(encrypted, output, with: @keypair, chunk_size: 43_211)
    assert_equal data, output.string
  end

  def test_decrypt_io_rejects_trailing_bytes_by_default
    data = "payload".b
    encrypted = StringIO.new("".b)
    PQCrypto::Seal.encrypt_io(StringIO.new(data), encrypted, size: data.bytesize, to: @keypair.public_key)
    encrypted.string << "TRAIL"
    encrypted.rewind
    output = StringIO.new("".b)
    assert_raises(PQCrypto::Seal::FormatError) do
      PQCrypto::Seal.decrypt_io(encrypted, output, with: @keypair)
    end
  end

  def test_decrypt_frame_io_tolerates_trailing_bytes
    data = "payload".b
    encrypted = StringIO.new("".b)
    PQCrypto::Seal.encrypt_io(StringIO.new(data), encrypted, size: data.bytesize, to: @keypair.public_key)
    encrypted.string << "TRAIL"
    encrypted.rewind
    output = StringIO.new("".b)
    PQCrypto::Seal.decrypt_frame_io(encrypted, output, with: @keypair)
    assert_equal data, output.string
    assert_equal "TRAIL", encrypted.read
  end

  def test_file_recipient_rebuild_and_dek_rotation
    bob = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      sealed = File.join(dir, "sealed")
      rebuilt = File.join(dir, "rebuilt")
      rotated = File.join(dir, "rotated")
      output = File.join(dir, "output")
      data = Random.new(9).bytes(1_300_017)
      File.binwrite(source, data)
      PQCrypto::Seal.encrypt_file(source, sealed, to: @keypair.public_key)
      PQCrypto::Seal.rebuild_recipients_file(
        sealed, rebuilt, with: @keypair,
        recipients: [@keypair.public_key, bob.public_key]
      )
      PQCrypto::Seal.decrypt_file(rebuilt, output, with: bob)
      assert_equal data, File.binread(output)

      rebuilt_size = File.size(rebuilt)
      PQCrypto::Seal.rotate_dek_file(
        rebuilt, rotated, with: @keypair,
        recipients: [@keypair.public_key, bob.public_key]
      )
      assert_equal rebuilt_size, File.size(rotated)
      refute_equal PQCrypto::Seal.digest(File.binread(rebuilt)), PQCrypto::Seal.digest(File.binread(rotated))
      PQCrypto::Seal.decrypt_file(rotated, output, with: bob)
      assert_equal data, File.binread(output)
    end
  end

  def test_rebuild_rejects_corrupted_payload_without_publishing
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      sealed = File.join(dir, "sealed")
      rebuilt = File.join(dir, "rebuilt")
      File.binwrite(source, "payload" * 50_000)
      PQCrypto::Seal.encrypt_file(source, sealed, to: @keypair.public_key)
      bytes = File.binread(sealed)
      info = PQCrypto::Seal.inspect_file(sealed)
      payload_offset = info.envelope_bytes - info.padded_inner_length - PQCrypto::Seal::Format::TAG_BYTES
      bytes.setbyte(payload_offset, bytes.getbyte(payload_offset) ^ 1)
      File.binwrite(sealed, bytes)
      assert_raises(PQCrypto::Seal::AuthenticationError) do
        PQCrypto::Seal.rebuild_recipients_file(
          sealed, rebuilt, with: @keypair, recipients: [@keypair.public_key]
        )
      end
      refute File.exist?(rebuilt)
    end
  end

  def test_failed_file_decrypt_does_not_publish_destination
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      sealed = File.join(dir, "sealed")
      destination = File.join(dir, "destination")
      File.binwrite(source, "important" * 100_000)
      PQCrypto::Seal.encrypt_file(source, sealed, to: @keypair.public_key)
      bytes = File.binread(sealed)
      bytes.setbyte(bytes.bytesize - 1, bytes.getbyte(-1) ^ 1)
      File.binwrite(sealed, bytes)
      assert_raises(PQCrypto::Seal::AuthenticationError) do
        PQCrypto::Seal.decrypt_file(sealed, destination, with: @keypair)
      end
      refute File.exist?(destination)
    end
  end

  def test_decrypt_file_resource_limit
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      sealed = File.join(dir, "sealed")
      destination = File.join(dir, "destination")
      File.binwrite(source, "x" * 1000)
      PQCrypto::Seal.encrypt_file(source, sealed, to: @keypair.public_key, padding: :none)
      assert_raises(PQCrypto::Seal::ResourceLimitError) do
        PQCrypto::Seal.decrypt_file(sealed, destination, with: @keypair, max_staging_bytes: 32)
      end
      refute File.exist?(destination)
    end
  end

  class PartialWriter
    def initialize(limit: 7)
      @limit = limit
      @buf = +"".b
    end
    attr_reader :buf
    def write(data)
      data = data.to_s.b
      take = [data.bytesize, @limit].min
      return 0 if take.zero? && !data.empty?
      @buf << data.byteslice(0, take)
      take
    end
    def binmode; self; end
    def flush; self; end
  end

  def test_encrypt_io_survives_partial_writes
    kp = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
    src = StringIO.new("hello-partial-write-world")
    out = PartialWriter.new(limit: 7)
    PQCrypto::Seal.encrypt_io(src, out, size: src.string.bytesize, to: kp.public_key, padding: :none)
    assert out.buf.bytesize > 32
    assert_equal "hello-partial-write-world", PQCrypto::Seal.decrypt(out.buf, with: kp)
  end

  def test_decrypt_io_survives_partial_writes
    data = "decrypted-partial-write" * 500
    envelope = PQCrypto::Seal.encrypt(data, to: @keypair.public_key, padding: :none)
    output = PartialWriter.new(limit: 5)

    PQCrypto::Seal.decrypt_io(StringIO.new(envelope), output, with: @keypair)

    assert_equal data, output.buf
  end

  class StalledWriter
    def write(_data)
      0
    end
  end

  def test_encrypt_io_rejects_writer_without_progress
    input = StringIO.new("x")
    assert_raises(IOError) do
      PQCrypto::Seal.encrypt_io(
        input, StalledWriter.new, size: 1, to: @keypair.public_key, padding: :none
      )
    end
  end

end

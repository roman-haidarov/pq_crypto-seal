# frozen_string_literal: true

require 'English'
require 'json'
require 'minitest/autorun'
require 'minitest/mock'
require 'stringio'
require 'tmpdir'
require 'pq_crypto/seal'

module SealTestSupport
  ALGORITHM = PQCrypto::Seal::WRAP_KEM_ALGORITHM
  ALICE = PQCrypto::HybridKEM.generate(ALGORITHM)
  BOB = PQCrypto::HybridKEM.generate(ALGORITHM)
  SEAL = PQCrypto::Seal
  FORMAT = PQCrypto::Seal::Format

  class DeterministicRandom
    def initialize(seed)
      @state = [seed].pack('Q>')
      @buffer = String.new
    end

    def bytes(length)
      buffer << next_block while buffer.bytesize < length
      buffer.slice!(0, length)
    end

    private

    attr_reader :buffer

    def next_block
      @state = SealTestSupport.native.sha256(@state)
    end
  end

  class Race
    def initialize(count)
      @count = count
      @gate = Queue.new
    end

    def run(&work)
      threads = Array.new(count) { spawn(&work) }
      count.times { gate << true }
      threads.map(&:value)
    end

    private

    attr_reader :count, :gate

    def spawn(&work)
      Thread.new { wait_then(&work) }
    end

    def wait_then
      gate.pop
      yield
    end
  end

  class FileScenario
    DATA = Random.new(9).bytes(1_300_017).freeze
    DESTINATIONS = { rebuild_corrupted: 'rebuilt', decrypt_corrupted: 'output', decrypt_limited: 'output' }.freeze

    def self.run
      Dir.mktmpdir('pq-seal-test') { |dir| yield new(dir) }
    end

    def initialize(dir)
      @dir = dir
    end

    def path(name)
      File.join(@dir, name)
    end

    def sealed(**options)
      source = path('source')
      File.binwrite(source, DATA)
      SEAL.encrypt_file(source, path('sealed'), to: [ALICE.public_key], **options)
    end

    def decrypted(sealed, **options)
      File.binread(SEAL.decrypt_file(sealed, path('output'), **options))
    end

    def open_as(file, keys)
      decrypted(public_send(file), with: keys)
    end

    def rebuilt
      SEAL.rebuild_recipients_file(sealed, path('rebuilt'), with: ALICE, recipients: [ALICE.public_key, BOB.public_key])
    end

    def added
      SEAL.add_recipient_file(sealed, path('added'), with: ALICE, recipient: BOB.public_key, current_recipients: [])
    end

    def rotated(source, **options)
      SEAL.rotate_dek_file(source, path('rotated'), with: ALICE, recipients: [BOB.public_key], **options)
    end

    def rotation_pair
      source = sealed
      [source, rotated(source)]
    end

    def reopen_rotated_with_fixed_padding
      source = sealed
      decrypted(rotated(source), with: BOB, required_padding: { to: File.size(source) })
    end

    def grown_capacity
      source = sealed(recipient_capacity: 1, padding: :none)
      SEAL.inspect_file(rotated(source, recipient_capacity: 4, padding: :none)).recipient_capacity
    end

    def rebuild_corrupted
      source = Crafting.corrupt_file(sealed) { |info| SealTestSupport.payload_offset(info) }
      SEAL.rebuild_recipients_file(source, path('rebuilt'), with: ALICE, recipients: [ALICE.public_key])
    end

    def decrypt_corrupted
      decrypted(Crafting.corrupt_file(sealed) { |info| info.envelope_bytes - 1 }, with: ALICE)
    end

    def decrypt_limited
      decrypted(sealed(padding: :none), with: ALICE, max_staging_bytes: 32)
    end

    def inspect_truncated
      source = sealed
      File.truncate(source, File.size(source) - 1)
      SEAL.inspect_file(source)
    end
  end

  class PartialWriter
    attr_reader :buffer

    def initialize(limit)
      @limit = limit
      @buffer = String.new
    end

    def write(data)
      taken = data.to_s.byteslice(0, @limit)
      buffer << taken
      taken.bytesize
    end
  end

  class StalledWriter
    def write(_data)
      0
    end
  end

  module Crafting
    module_function

    def seal_encrypt(data, public_key, options = {})
      SEAL.encrypt(data, to: public_key, **options)
    end

    def open_payload(envelope, associated_data)
      parsed = internal(:Envelope).parse(envelope)
      native.aegis256_decrypt(parsed.unwrap_dek(ALICE), parsed.header.payload_nonce, associated_data,
                              parsed.ciphertext, parsed.tag)
    end

    def noncanonical_padme_envelope
      identity = internal(:PayloadIdentity).generate
      inner = "#{FORMAT.inner_prefix(4, 0)}data"
      header = noncanonical_header(identity, inner.bytesize)
      header + single_section(identity, header) + sealed_inner(identity, header, inner)
    end

    def sealed_inner(identity, header, inner)
      native.aegis256_encrypt(identity.dek, identity.payload_nonce, native.sha256(header), inner).join
    end

    def noncanonical_header(identity, inner_length)
      FORMAT.build_header(
        payload_id: identity.payload_id, payload_nonce: identity.payload_nonce, recipient_capacity: 1,
        slot_size: 2048, padded_inner_length: inner_length, public_metadata: '',
        padding_policy_id: FORMAT::PADDING_PADME
      )
    end

    def single_section(identity, header)
      spec = internal(:SectionSpec).new(
        capacity: 1, slot_size: 2048, payload_id: identity.payload_id, header_hash: native.sha256(header)
      )
      internal(:RecipientSectionBuilder).new(spec, [ALICE.public_key], identity.dek).call
    end

    def decrypt_for_each(envelope, credentials = [ALICE, BOB])
      credentials.map { |keys| SEAL.decrypt(envelope, with: keys) }
    end

    def corrupt_file(file)
      bytes = File.binread(file)
      File.binwrite(file, SealTestSupport.flip_byte(bytes, yield(SEAL.inspect_envelope(bytes))))
      file
    end

    def encrypt_declared(size)
      SEAL.encrypt_io(StringIO.new('x'), StringIO.new(String.new), size: size, to: ALICE.public_key)
    end

    def copy_slot(envelope, offset, slot_size)
      envelope.dup.tap { |copy| copy[offset + slot_size, slot_size] = envelope.byteslice(offset, slot_size) }
    end

    def stream_encrypt(data, public_key, options = {})
      output = StringIO.new(String.new)
      SEAL.encrypt_io(StringIO.new(data), output, size: data.bytesize, to: public_key, **options)
      output.string
    end

    def stream_decrypt(envelope, options)
      output = StringIO.new(String.new)
      SEAL.decrypt_io(StringIO.new(envelope), output, **options)
      output.string
    end

    def without_section(envelope)
      header = FORMAT.parse_header(envelope)
      raw = header.raw
      raw + envelope.byteslice((raw.bytesize + FORMAT.section_length(header))..)
    end

    def vector_public_key(vector)
      PQCrypto::HybridKEM.public_key_from_bytes(ALGORITHM, hex(vector.fetch('pk')))
    end

    def vector_keypair(vector)
      secret_key = PQCrypto::HybridKEM.secret_key_from_bytes(ALGORITHM, hex(vector.fetch('sk')))
      PQCrypto::HybridKEM::Keypair.new(vector_public_key(vector), secret_key)
    end
  end

  include Crafting

  module_function

  def internal(name)
    SEAL.const_get(name, false)
  end

  def native
    internal(:Native)
  end

  def fresh_keypair
    PQCrypto::HybridKEM.generate(ALGORITHM)
  end

  def flip_byte(bytes, index)
    bytes.dup.tap { |copy| copy.setbyte(index, copy.getbyte(index) ^ 1) }
  end

  def hex(value)
    [value].pack('H*')
  end

  def fixture(name)
    JSON.parse(File.read(File.expand_path("fixtures/#{name}", __dir__)))
  end

  def payload_offset(info)
    info.envelope_bytes - info.padded_inner_length - FORMAT::TAG_BYTES
  end

  def in_tmpdir(&block)
    Dir.mktmpdir('pq-seal-test', &block)
  end

  def with_random(seed, &block)
    stream = DeterministicRandom.new(seed)
    native.stub(:random_bytes, ->(length) { stream.bytes(length) }, &block)
  end

  def chunks(bytes, size)
    (0...bytes.bytesize).step(size).map { |offset| bytes.byteslice(offset, size) }
  end

  def to_str_object(&block)
    Object.new.tap { |object| object.define_singleton_method(:to_str, &block) }
  end

  def concurrent_outcomes(state, payload)
    Race.new(8).run { Array.new(8) { attempt_update(state, payload) } }.flatten.uniq.sort
  end

  def attempt_update(state, payload)
    state.update(payload)
    :updated
  rescue RuntimeError
    raise unless $ERROR_INFO.message == 'AEGIS state is in use'

    :busy
  end

  def compact_heap
    GC.verify_compaction_references(expand_heap: true, toward: :empty)
  rescue ArgumentError
    GC.compact
  end
end

# frozen_string_literal: true

require 'tempfile'
require 'fileutils'

module PQCrypto
  module Seal
    module IOHelpers
      module_function

      def write_all(io, data)
        CompleteWriter.new(io, data).call
      end

      def write_secret(io, data)
        CompleteWriter.new(io, data, wipe_chunks: true).call
      ensure
        Secrets.wipe!(data)
      end

      def ensure_eof(io, message)
        raise FormatError, message unless io.read(1).to_s.empty?
      end

      def validate_chunk_size(value)
        size = Integer(value)
        raise ArgumentError, 'chunk_size must be positive' unless size.positive?

        size
      end

      def read_header(input)
        reader = ExactReader.new(input, 'truncated envelope')
        prefix = reader.read(Format::HEADER_PREFIX_BYTES)
        length = Format::HeaderCodec.declared_length(prefix)
        Format.parse_header(prefix + reader.read(length - prefix.bytesize))
      end

      def staging_file(prefix, directory = nil)
        file = Tempfile.new([prefix, '.bin'], directory)
        file.binmode
        file.chmod(0o600)
        unlink_open_file(file)
        ready = file
      ensure
        close_tempfile(file) unless ready
      end

      def with_tempfile(prefix, directory)
        file = staging_file(prefix, directory)
        yield file
      ensure
        close_tempfile(file)
      end

      def durable_close(file)
        file.flush
        file.fsync
        file.close
      end

      def unlink_open_file(file)
        file.unlink
      rescue SystemCallError, IOError, NotImplementedError
        nil
      end

      def close_tempfile(file)
        file&.close!
      rescue StandardError
        nil
      end
    end

    class CompleteWriter
      def initialize(io, data, wipe_chunks: false)
        @io = io
        @data = data
        @wipe_chunks = wipe_chunks
        @offset = 0
      end

      def call
        advance while offset < data.bytesize
        offset
      end

      private

      attr_reader :io, :data, :wipe_chunks, :offset

      def advance
        remaining = data.bytesize - offset
        chunk = pending(remaining)
        written = io.write(chunk)
        raise IOError, 'output made no write progress' unless written.is_a?(Integer) && written.positive?
        raise IOError, 'output reported writing more bytes than provided' if written > remaining

        @offset += written
      ensure
        Secrets.wipe!(chunk) if wipe_chunks && !chunk.equal?(data)
      end

      def pending(remaining)
        return data.byteslice(offset, remaining) unless wipe_chunks

        offset.zero? ? data : data.unpack1("@#{offset}a*")
      end
    end

    class ExactReader
      def self.rewound(io, message, **options)
        io.rewind
        new(io, message, **options)
      end

      def initialize(io, message, wipe_reads: false)
        @io = io
        @message = message
        @wipe_reads = wipe_reads
      end

      def read(length)
        count = Integer(length)
        buffer = String.new(capacity: count)
        append(buffer, count) while buffer.bytesize < count
        complete = buffer
      ensure
        Secrets.wipe!(buffer) unless complete
      end

      def each_chunk(length, chunk_size, &block)
        total = Integer(length)
        0.step(total - 1, chunk_size) { |offset| with_chunk([chunk_size, total - offset].min, &block) }
      end

      def eof?
        io.read(1).to_s.empty?
      end

      private

      attr_reader :io, :message, :wipe_reads

      def with_chunk(size)
        chunk = read(size)
        yield chunk
      ensure
        Secrets.wipe!(chunk)
      end

      def append(buffer, count)
        remaining = count - buffer.bytesize
        chunk = io.read(remaining)
        raise EOFError, message if chunk.nil? || chunk.empty?
        raise IOError, 'input returned more bytes than requested' if chunk.bytesize > remaining

        buffer << Binary.view(chunk)
      ensure
        Secrets.wipe!(chunk) if wipe_reads
      end
    end

    class AtomicDestination
      def initialize(destination)
        @path = File.expand_path(destination)
        @directory = File.dirname(path)
      end

      def write
        FileUtils.mkdir_p(directory)
        tempfile = Tempfile.new([".#{File.basename(path)}.", '.pqcseal'], directory)
        tempfile.binmode
        tempfile.chmod(0o600)
        yield tempfile
        publish(tempfile)
      ensure
        IOHelpers.close_tempfile(tempfile)
      end

      private

      attr_reader :path, :directory

      def publish(file)
        IOHelpers.durable_close(file)
        File.rename(file.path, path)
        fsync_directory
        path
      end

      def fsync_directory
        File.open(directory, 'r', &:fsync)
      rescue SystemCallError, IOError
        nil
      end
    end

    class StreamEnvelope
      include EnvelopeParts

      attr_reader :header, :section, :envelope_bytes, :header_hash

      def self.read(input, limits)
        header = IOHelpers.read_header(input)
        section_bytes = ExactReader.new(input, 'truncated envelope').read(Format.section_length(header))
        envelope = new(header, Format.parse_section(section_bytes, 0, header))
        limits.check_declared(header, envelope.envelope_bytes)
        envelope
      end

      def initialize(header, section)
        raw = header.raw
        @header = header
        @section = section
        @envelope_bytes = raw.bytesize + section.raw.bytesize + header.padded_inner_length + Format::TAG_BYTES
        @header_hash = Native.sha256(raw)
      end
    end

    class AuthenticatedPass
      def initialize(envelope, dek, chunk_size)
        @envelope = envelope
        @decryptor = envelope.payload_decryptor(dek)
        @chunk_size = chunk_size
      end

      def copy(input, output)
        reader = ExactReader.new(input, 'truncated envelope')
        reader.each_chunk(envelope.header.padded_inner_length, chunk_size) { |chunk| forward(output, chunk) }
        reader.read(Format::TAG_BYTES).tap { |tag| decryptor.final(tag) }
      end

      def rewrite(input, output, section)
        IOHelpers.write_all(output, envelope.header.raw + section)
        tag = copy(input, output)
        IOHelpers.ensure_eof(input, 'trailing bytes after envelope')
        IOHelpers.write_all(output, tag)
      end

      private

      attr_reader :envelope, :decryptor, :chunk_size

      def forward(output, ciphertext)
        Secrets.wipe!(decryptor.update(ciphertext))
        IOHelpers.write_all(output, ciphertext)
      end
    end
  end
end

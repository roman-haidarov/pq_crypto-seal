# frozen_string_literal: true

require "tempfile"
require "fileutils"

module PQCrypto
  module Seal
    module IOHelpers
      module_function

      def write_all(io, data)
        bytes = String(data).b
        offset = 0
        while offset < bytes.bytesize
          written = io.write(bytes.byteslice(offset, bytes.bytesize - offset))
          raise IOError, "output made no write progress" unless written.is_a?(Integer) && written.positive?

          offset += written
        end
        bytes.bytesize
      end

      def read_exact(io, length, message: "truncated envelope")
        length = Integer(length)
        return "".b if length.zero?

        buffer = +"".b
        while buffer.bytesize < length
          chunk = io.read(length - buffer.bytesize)
          raise EOFError, message unless chunk && !chunk.empty?

          buffer << chunk.b
        end
        buffer
      end

      def each_exact_chunk(io, length, chunk_size, message: "truncated envelope")
        return enum_for(__method__, io, length, chunk_size, message: message) unless block_given?

        remaining = Integer(length)
        while remaining.positive?
          chunk = read_exact(io, [remaining, chunk_size].min, message: message)
          yield chunk
          remaining -= chunk.bytesize
        end
      end

      def copy_exact(input, output, length, chunk_size, message: "truncated envelope")
        each_exact_chunk(input, length, chunk_size, message: message) { |chunk| write_all(output, chunk) }
        length
      end

      def ensure_eof!(io, message)
        raise FormatError, message unless io.read(1).nil?
      end

      def validate_chunk_size(value)
        size = Integer(value)
        raise ArgumentError, "chunk_size must be positive" unless size.positive?

        size
      end

      def read_header(input)
        initial = read_exact(input, Format::HEADER_PREFIX_BYTES)
        header_length = initial.byteslice(Format::MAGIC.bytesize + 1, 4).unpack1("N")
        valid = header_length.between?(initial.bytesize, Format::MAX_HEADER_BYTES)
        raise FormatError, "invalid header length" unless valid

        Format.parse_header(initial + read_exact(input, header_length - initial.bytesize))
      end

      def staging_file(prefix, directory = nil)
        file = Tempfile.new([prefix, ".bin"], directory)
        file.binmode
        file.chmod(0o600)
        unlink_open_file(file)
        file
      end

      def unlink_open_file(file)
        file.unlink
      rescue SystemCallError, IOError, NotImplementedError
        nil
      end

      def close_tempfile(file)
        file.close!
      rescue StandardError
        nil
      end
    end

    class AtomicDestination
      def initialize(destination)
        @path = File.expand_path(destination)
        @directory = File.dirname(@path)
      end

      def write
        FileUtils.mkdir_p(@directory)
        tempfile = build_tempfile
        yield tempfile
        publish(tempfile)
        @path
      ensure
        IOHelpers.close_tempfile(tempfile) if tempfile
      end

      private

      def build_tempfile
        file = Tempfile.new([".#{File.basename(@path)}.", ".pqcseal"], @directory)
        file.binmode
        file.chmod(0o600)
        file
      end

      def publish(file)
        file.flush
        file.fsync
        file.close
        File.rename(file.path, @path)
        fsync_directory
      end

      def fsync_directory
        File.open(@directory, "r") { |directory| directory.fsync }
      rescue SystemCallError, IOError
        nil
      end
    end

    class StreamEnvelope
      attr_reader :header, :section, :envelope_bytes

      def self.read(input, limits)
        header = IOHelpers.read_header(input)
        section = Format.parse_section(
          IOHelpers.read_exact(input, Format.section_length(header)), 0, header
        )
        total = header.raw.bytesize + section.raw.bytesize +
                header.padded_inner_length + Format::TAG_BYTES
        limits.check_declared!(header, envelope_bytes: total)

        new(header, section, total)
      end

      def initialize(header, section, envelope_bytes)
        @header = header
        @section = section
        @envelope_bytes = envelope_bytes
      end

      def header_hash
        @header_hash ||= Native.sha256(header.raw)
      end

      def unwrap_dek(credentials)
        RecipientSectionOpener.new(header, section, credentials).call
      end

      def stream_verified_payload(input, dek, chunk_size, strict_eof: true)
        decryptor = Native::Decryptor.new(dek, header.payload_nonce, header_hash)
        IOHelpers.each_exact_chunk(input, header.padded_inner_length, chunk_size) do |ciphertext|
          plaintext = decryptor.update(ciphertext)
          begin
            yield ciphertext, plaintext
          ensure
            Secrets.wipe!(plaintext)
          end
        end
        tag = IOHelpers.read_exact(input, Format::TAG_BYTES)
        decryptor.final(tag)
        IOHelpers.ensure_eof!(input, "trailing bytes after envelope") if strict_eof
        tag
      end

      def inspection
        Inspection.build(header, section, envelope_bytes: envelope_bytes)
      end
    end
  end
end

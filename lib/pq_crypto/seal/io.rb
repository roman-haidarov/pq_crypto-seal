# frozen_string_literal: true

require "tempfile"
require "fileutils"

module PQCrypto
  module Seal
    module IOAPI
      DEFAULT_CHUNK_SIZE = 1024 * 1024
      module_function

      def encrypt_io(input, output, size:, to:, metadata: "".b, public_metadata: "".b,
                     recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                     slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme,
                     chunk_size: DEFAULT_CHUNK_SIZE, strict_size: true)
        content_size = Integer(size)
        raise ArgumentError, "size must be non-negative" if content_size.negative?
        metadata = String(metadata).b
        seal(:validate_private_metadata!, metadata)
        recipients = seal(:normalize_public_keys, to)
        capacity = Format.validate_capacity!(recipient_capacity, recipients.length)
        slot_size = Format.validate_slot_size!(slot_size)
        chunk_size = validate_chunk_size(chunk_size)

        parts = nil
        parts = seal(
          :materialize_crypto_parts,
          recipients: recipients, capacity: capacity, slot_size: slot_size,
          padding: padding, public_metadata: public_metadata,
          content_size: content_size, metadata_size: metadata.bytesize
        )
        output.write(parts[:header])
        output.write(parts[:section])
        encryptor = Native::Encryptor.new(parts[:dek], parts[:payload_nonce], parts[:header_hash])
        output.write(encryptor.update(parts[:inner_prefix]))
        output.write(encryptor.update(metadata)) unless metadata.empty?
        copied = copy_exact_encrypted(input, output, encryptor, content_size, chunk_size)
        raise EOFError, "input ended after #{copied} of #{content_size} bytes" unless copied == content_size
        if strict_size
          raise ArgumentError, "input contains more bytes than declared size" unless input.read(1).nil?
        end
        write_random_encrypted(output, encryptor, parts[:padded_inner_length] - parts[:raw_inner_length], chunk_size)
        output.write(encryptor.final)
        output
      ensure
        seal(:wipe_string!, parts[:dek]) if parts
        seal(:wipe_string!, metadata) if metadata.is_a?(String) && !metadata.frozen?
      end

      def decrypt_io(input, output, with:, staging_directory: nil, chunk_size: DEFAULT_CHUNK_SIZE,
                     strict_eof: true, **limits)
        limits = Format::LIMIT_DEFAULTS.merge(limits)
        chunk_size = validate_chunk_size(chunk_size)
        staging = new_staging("pqcrypto-seal-inner", staging_directory)
        opened = decrypt_to_staging(
          input, staging, with: with, chunk_size: chunk_size, strict_eof: strict_eof, **limits
        )
        staging.flush
        staging.rewind
        content_offset, content_length, metadata = parse_verified_staging(staging, opened[:header].padded_inner_length)
        if content_length > Integer(limits[:max_plaintext_bytes])
          seal(:wipe_string!, metadata)
          raise ResourceLimitError,
                "plaintext #{content_length} exceeds max_plaintext_bytes #{limits[:max_plaintext_bytes]}"
        end
        staging.seek(content_offset, ::IO::SEEK_SET)
        copy_exact(staging, output, content_length, chunk_size)
        Opened.from_header(opened[:header], opened[:section], data: nil, metadata: metadata)
      ensure
        staging.close! if defined?(staging) && staging
      end

      def decrypt_frame_io(input, output, with:, **options)
        decrypt_io(input, output, with: with, strict_eof: false, **options)
      end

      def encrypt_frame_io(input, output, size:, to:, **options)
        encrypt_io(input, output, size: size, to: to, strict_size: false, **options)
      end

      def encrypt_file(source, destination, **options)
        File.open(source, "rb") do |input|
          size = input.stat.size
          atomic_destination(destination) do |tmp|
            encrypt_io(input, tmp, size: size, strict_size: true, **options)
          end
        end
        destination
      end

      def decrypt_file(source, destination, with:, staging_directory: nil,
                       chunk_size: DEFAULT_CHUNK_SIZE, **limits)
        File.open(source, "rb") do |input|
          atomic_destination(destination) do |tmp|
            decrypt_io(
              input, tmp, with: with, staging_directory: staging_directory,
              chunk_size: chunk_size, strict_eof: true, **limits
            )
          end
        end
        destination
      end

      def rebuild_recipients_file(source, destination, with:, recipients:, chunk_size: DEFAULT_CHUNK_SIZE)
        chunk_size = validate_chunk_size(chunk_size)
        File.open(source, "rb") do |input|
          header = read_header(input)
          old_section = Format.parse_section(read_exact(input, Format.section_length(header)), 0, header)
          dek = seal(:unwrap_dek, header, old_section, with)
          public_keys = seal(:normalize_public_keys, recipients)
          Format.validate_capacity!(header.recipient_capacity, public_keys.length)
          new_section = seal(
            :build_recipient_section,
            recipients: public_keys, capacity: header.recipient_capacity,
            slot_size: header.slot_size, payload_id: header.payload_id,
            header_hash: Native.sha256(header.raw), dek: dek,
            wrap_suite_id: Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
          )
          atomic_destination(destination) do |tmp|
            tmp.write(header.raw)
            tmp.write(new_section)
            verifier = Native::Decryptor.new(dek, header.payload_nonce, Native.sha256(header.raw))
            remaining = header.padded_inner_length
            while remaining.positive?
              take = [remaining, chunk_size].min
              ciphertext_chunk = read_exact(input, take)
              tmp.write(ciphertext_chunk)
              seal(:wipe_string!, verifier.update(ciphertext_chunk))
              remaining -= take
            end
            payload_tag = read_exact(input, Format::TAG_BYTES)
            raise FormatError, "trailing bytes after envelope" unless input.read(1).nil?
            verifier.final(payload_tag)
            tmp.write(payload_tag)
          end
        ensure
          seal(:wipe_string!, dek) if defined?(dek)
        end
        destination
      end

      def add_recipient_file(source, destination, with:, recipient:, current_recipients:, **options)
        rebuild_recipients_file(
          source, destination, with: with,
          recipients: Array(current_recipients) + [recipient], **options
        )
      end

      def drop_recipient_stanza_file(source, destination, with:, remaining_recipients:, **options)
        rebuild_recipients_file(source, destination, with: with, recipients: remaining_recipients, **options)
      end

      def rotate_dek_file(source, destination, with:, recipients:, padding: :preserve,
                          staging_directory: nil, chunk_size: DEFAULT_CHUNK_SIZE)
        plaintext = new_staging("pqcrypto-seal-rotation", staging_directory)
        opened = nil
        File.open(source, "rb") do |input|
          opened = decrypt_io(input, plaintext, with: with,
                              staging_directory: staging_directory, chunk_size: chunk_size, strict_eof: true)
        end
        plaintext.flush
        plaintext.rewind
        info = inspect_file(source)
        padding = { to: info.envelope_bytes } if padding == :preserve
        atomic_destination(destination) do |tmp|
          encrypt_io(
            plaintext, tmp, size: plaintext.stat.size, to: recipients,
            metadata: opened.metadata, public_metadata: opened.public_metadata,
            recipient_capacity: info.recipient_capacity, slot_size: info.slot_size,
            padding: padding, chunk_size: chunk_size, strict_size: true
          )
        end
        destination
      ensure
        plaintext.close! if defined?(plaintext) && plaintext
        seal(:wipe_string!, opened.metadata) if defined?(opened) && opened && opened.metadata
      end

      def inspect_file(source)
        File.open(source, "rb") do |input|
          header = read_header(input)
          section = Format.parse_section(read_exact(input, Format.section_length(header)), 0, header)
          total = header.raw.bytesize + section.raw.bytesize + header.padded_inner_length + Format::TAG_BYTES
          raise FormatError, "file length does not match envelope" unless File.size(source) == total
          Inspection.from_header(header, section, envelope_bytes: total)
        end
      end

      def decrypt_to_staging(input, staging, with:, chunk_size:, strict_eof:, **limits)
        limits = Format::LIMIT_DEFAULTS.merge(limits)
        header = read_header(input)
        Format.check_resource_limits!(
          padded_inner_length: header.padded_inner_length, **Format.pre_auth_limits(limits)
        )
        section = Format.parse_section(read_exact(input, Format.section_length(header)), 0, header)
        estimated = header.raw.bytesize + section.raw.bytesize + header.padded_inner_length + Format::TAG_BYTES
        Format.check_resource_limits!(
          padded_inner_length: header.padded_inner_length,
          envelope_bytes: estimated, **Format.pre_auth_limits(limits)
        )
        dek = seal(:unwrap_dek, header, section, with)
        decryptor = Native::Decryptor.new(dek, header.payload_nonce, Native.sha256(header.raw))
        remaining = header.padded_inner_length
        while remaining.positive?
          take = [remaining, chunk_size].min
          staging.write(decryptor.update(read_exact(input, take)))
          remaining -= take
        end
        tag = read_exact(input, Format::TAG_BYTES)
        raise FormatError, "trailing bytes after envelope" if strict_eof && !input.read(1).nil?
        decryptor.final(tag)
        { header: header, section: section }
      ensure
        seal(:wipe_string!, dek) if defined?(dek)
      end

      def parse_verified_staging(staging, expected_size)
        raise FormatError, "staging size mismatch" unless staging.stat.size == expected_size
        staging.rewind
        prefix = read_exact(staging, 14)
        version = prefix.getbyte(0)
        flags = prefix.getbyte(1)
        raise FormatError, "unsupported inner version" unless version == Format::INNER_VERSION
        raise FormatError, "unknown inner flags" unless flags == Format::INNER_FLAGS
        hi, lo, metadata_length = prefix.byteslice(2, 12).unpack("NNN")
        content_length = (hi << 32) | lo
        raise FormatError, "private metadata is too large" if metadata_length > Format::MAX_PRIVATE_METADATA_BYTES
        minimum = 14 + metadata_length + content_length
        raise FormatError, "inner lengths exceed authenticated frame" if minimum > expected_size
        metadata = read_exact(staging, metadata_length)
        [14 + metadata_length, content_length, metadata]
      end

      def read_header(input)
        prefix_len = Format::MAGIC.bytesize + 1 + 4
        initial = read_exact(input, prefix_len)
        header_length = initial.byteslice(Format::MAGIC.bytesize + 1, 4).unpack1("N")
        raise FormatError, "invalid header length" if header_length < initial.bytesize || header_length > Format::MAX_HEADER_BYTES
        Format.parse_header(initial + read_exact(input, header_length - initial.bytesize))
      end

      def seal(name, *args, **kwargs)
        Seal.send(name, *args, **kwargs)
      end

      def atomic_destination(destination)
        path = File.expand_path(destination)
        directory = File.dirname(path)
        FileUtils.mkdir_p(directory)
        temp = Tempfile.new([".#{File.basename(path)}.", ".pqcseal"], directory)
        temp.binmode
        temp.chmod(0o600)
        begin
          yield temp
          temp.flush
          temp.fsync
          temp.close
          File.rename(temp.path, path)
          fsync_directory(directory)
        ensure
          temp.close! rescue nil
        end
      end

      def fsync_directory(directory)
        File.open(directory, "r") { |dir| dir.fsync }
      rescue SystemCallError, IOError
        nil
      end

      def copy_exact_encrypted(input, output, encryptor, length, chunk_size)
        copied = 0
        while copied < length
          chunk = input.read([chunk_size, length - copied].min)
          break unless chunk && !chunk.empty?
          chunk = chunk.b
          output.write(encryptor.update(chunk))
          copied += chunk.bytesize
        end
        copied
      end

      def write_random_encrypted(output, encryptor, length, chunk_size)
        remaining = length
        while remaining.positive?
          take = [remaining, chunk_size].min
          random = Native.random_bytes(take)
          output.write(encryptor.update(random))
          seal(:wipe_string!, random)
          remaining -= take
        end
      end

      def copy_exact(input, output, length, chunk_size)
        remaining = length
        while remaining.positive?
          chunk = input.read([remaining, chunk_size].min)
          raise EOFError, "staging input is truncated" unless chunk && !chunk.empty?
          output.write(chunk)
          remaining -= chunk.bytesize
        end
      end

      def read_exact(io, length)
        return "".b if length.zero?
        buffer = +"".b
        while buffer.bytesize < length
          chunk = io.read(length - buffer.bytesize)
          raise EOFError, "truncated envelope" unless chunk && !chunk.empty?
          buffer << chunk.b
        end
        buffer
      end

      def new_staging(prefix, staging_directory)
        tempfile = Tempfile.new([prefix, ".bin"], staging_directory)
        tempfile.binmode
        tempfile.chmod(0o600)
        unlink_open_tempfile(tempfile)
        tempfile
      end

      def unlink_open_tempfile(tempfile)
        tempfile.unlink
      rescue SystemCallError, IOError, NotImplementedError
        nil
      end

      def validate_chunk_size(value)
        size = Integer(value)
        raise ArgumentError, "chunk_size must be positive" unless size.positive?
        size
      end
    end
  end
end

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
        Seal.send(:validate_private_metadata!, metadata)
        recipients = Seal.send(:normalize_public_keys, to)
        capacity = Format.validate_capacity!(recipient_capacity, recipients.length)
        slot_size = Format.validate_slot_size!(slot_size)
        chunk_size = validate_chunk_size(chunk_size)
        padding_policy_id = Format.padding_policy_id_for(padding)

        payload_id = Native.random_bytes(Format::PAYLOAD_ID_BYTES)
        payload_nonce = Native.random_bytes(Format::NONCE_BYTES)
        dek = Native.random_bytes(Format::DEK_BYTES)
        prefix = Format.inner_prefix(content_size, metadata.bytesize)
        raw_inner_length = prefix.bytesize + metadata.bytesize + content_size
        placeholder = Format.build_header(
          payload_id: payload_id, payload_nonce: payload_nonce,
          recipient_capacity: capacity, slot_size: slot_size,
          padded_inner_length: raw_inner_length, public_metadata: public_metadata,
          padding_policy_id: padding_policy_id
        )
        fixed = placeholder.bytesize + Format.section_length_for(capacity, slot_size) + Format::TAG_BYTES
        target = Padding.target(fixed + raw_inner_length, padding)
        padded_inner_length = target - fixed
        header = Format.build_header(
          payload_id: payload_id, payload_nonce: payload_nonce,
          recipient_capacity: capacity, slot_size: slot_size,
          padded_inner_length: padded_inner_length, public_metadata: public_metadata,
          padding_policy_id: padding_policy_id
        )
        header_hash = Native.sha256(header)
        section = Seal.send(
          :build_recipient_section,
          recipients: recipients, capacity: capacity, slot_size: slot_size,
          payload_id: payload_id, header_hash: header_hash, dek: dek,
          wrap_suite_id: Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
        )
        output.write(header)
        output.write(section)
        encryptor = Native::Encryptor.new(dek, payload_nonce, header_hash)
        output.write(encryptor.update(prefix))
        output.write(encryptor.update(metadata)) unless metadata.empty?
        copied = copy_exact_encrypted(input, output, encryptor, content_size, chunk_size)
        raise EOFError, "input ended after #{copied} of #{content_size} bytes" unless copied == content_size
        if strict_size
          extra = input.read(1)
          raise ArgumentError, "input contains more bytes than declared size" unless extra.nil?
        end
        padding_length = padded_inner_length - raw_inner_length
        write_random_encrypted(output, encryptor, padding_length, chunk_size)
        output.write(encryptor.final)
        output
      ensure
        Seal.send(:wipe_string!, dek) if defined?(dek)
        Seal.send(:wipe_string!, metadata) if defined?(metadata) && metadata.is_a?(String) && !metadata.frozen?
      end

      def decrypt_io(input, output, with:, staging_directory: nil, chunk_size: DEFAULT_CHUNK_SIZE,
                     strict_eof: true,
                     max_staging_bytes: Format::DEFAULT_MAX_STAGING_BYTES,
                     max_plaintext_bytes: Format::DEFAULT_MAX_PLAINTEXT_BYTES,
                     max_envelope_bytes: Format::DEFAULT_MAX_ENVELOPE_BYTES)
        chunk_size = validate_chunk_size(chunk_size)
        staging = Tempfile.new(["pqcrypto-seal-inner", ".bin"], staging_directory)
        staging.binmode
        staging.chmod(0o600)
        unlink_open_tempfile(staging)
        opened = decrypt_to_staging(
          input, staging, with: with, chunk_size: chunk_size, strict_eof: strict_eof,
          max_staging_bytes: max_staging_bytes,
          max_plaintext_bytes: max_plaintext_bytes,
          max_envelope_bytes: max_envelope_bytes
        )
        staging.flush
        staging.rewind
        content_offset, content_length, metadata = parse_verified_staging(staging, opened[:header].padded_inner_length)
        if content_length > Integer(max_plaintext_bytes)
          raise ResourceLimitError,
                "plaintext #{content_length} exceeds max_plaintext_bytes #{max_plaintext_bytes}"
        end
        staging.seek(content_offset, ::IO::SEEK_SET)
        copy_exact(staging, output, content_length, chunk_size)
        Opened.new(
          data: nil, metadata: metadata, public_metadata: opened[:header].public_metadata,
          payload_id: opened[:header].payload_id,
          content_suite_id: opened[:header].content_suite_id,
          wrap_suite_id: opened[:section].wrap_suite_id,
          padding_policy_id: opened[:header].padding_policy_id
        )
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

      def decrypt_file(source, destination, with:, staging_directory: nil, chunk_size: DEFAULT_CHUNK_SIZE,
                       max_staging_bytes: Format::DEFAULT_MAX_STAGING_BYTES,
                       max_plaintext_bytes: Format::DEFAULT_MAX_PLAINTEXT_BYTES,
                       max_envelope_bytes: Format::DEFAULT_MAX_ENVELOPE_BYTES)
        File.open(source, "rb") do |input|
          atomic_destination(destination) do |tmp|
            decrypt_io(
              input, tmp, with: with, staging_directory: staging_directory,
              chunk_size: chunk_size, strict_eof: true,
              max_staging_bytes: max_staging_bytes,
              max_plaintext_bytes: max_plaintext_bytes,
              max_envelope_bytes: max_envelope_bytes
            )
          end
        end
        destination
      end

      def rebuild_recipients_file(source, destination, with:, recipients:, chunk_size: DEFAULT_CHUNK_SIZE)
        chunk_size = validate_chunk_size(chunk_size)
        File.open(source, "rb") do |input|
          initial = read_exact(input, Format::MAGIC.bytesize + 1 + 4)
          header_length = initial.byteslice(Format::MAGIC.bytesize + 1, 4).unpack1("N")
          raise FormatError, "invalid header length" if header_length < initial.bytesize || header_length > Format::MAX_HEADER_BYTES
          header = Format.parse_header(initial + read_exact(input, header_length - initial.bytesize))
          old_section_bytes = read_exact(input, Format.section_length(header))
          old_section = Format.parse_section(old_section_bytes, 0, header)
          dek = Seal.send(:unwrap_dek, header, old_section, with)
          public_keys = Seal.send(:normalize_public_keys, recipients)
          Format.validate_capacity!(header.recipient_capacity, public_keys.length)
          new_section = Seal.send(
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
              plaintext_chunk = verifier.update(ciphertext_chunk)
              Seal.send(:wipe_string!, plaintext_chunk)
              remaining -= take
            end
            payload_tag = read_exact(input, Format::TAG_BYTES)
            raise FormatError, "trailing bytes after envelope" unless input.read(1).nil?
            verifier.final(payload_tag)
            tmp.write(payload_tag)
          end
        ensure
          Seal.send(:wipe_string!, dek) if defined?(dek)
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
        plaintext = Tempfile.new(["pqcrypto-seal-rotation", ".bin"], staging_directory)
        plaintext.binmode
        plaintext.chmod(0o600)
        unlink_open_tempfile(plaintext)
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
        Seal.send(:wipe_string!, opened.metadata) if defined?(opened) && opened && opened.metadata
      end

      def inspect_file(source)
        File.open(source, "rb") do |input|
          initial = read_exact(input, Format::MAGIC.bytesize + 1 + 4)
          header_length = initial.byteslice(Format::MAGIC.bytesize + 1, 4).unpack1("N")
          raise FormatError, "invalid header length" if header_length < initial.bytesize || header_length > Format::MAX_HEADER_BYTES
          header = Format.parse_header(initial + read_exact(input, header_length - initial.bytesize))
          section = Format.parse_section(read_exact(input, Format.section_length(header)), 0, header)
          total = header.raw.bytesize + section.raw.bytesize + header.padded_inner_length + Format::TAG_BYTES
          raise FormatError, "file length does not match envelope" unless File.size(source) == total
          Inspection.new(
            payload_id: header.payload_id, public_metadata: header.public_metadata,
            recipient_capacity: header.recipient_capacity, slot_size: header.slot_size,
            padded_inner_length: header.padded_inner_length,
            content_suite_id: header.content_suite_id, wrap_suite_id: section.wrap_suite_id,
            padding_policy_id: header.padding_policy_id,
            envelope_bytes: total
          )
        end
      end

      def decrypt_to_staging(input, staging, with:, chunk_size:, strict_eof:,
                             max_staging_bytes:, max_plaintext_bytes:, max_envelope_bytes:)
        initial = read_exact(input, Format::MAGIC.bytesize + 1 + 4)
        header_length = initial.byteslice(Format::MAGIC.bytesize + 1, 4).unpack1("N")
        raise FormatError, "invalid header length" if header_length < initial.bytesize || header_length > Format::MAX_HEADER_BYTES
        rest = read_exact(input, header_length - initial.bytesize)
        header = Format.parse_header(initial + rest)
        Format.check_resource_limits!(
          padded_inner_length: header.padded_inner_length,
          max_staging_bytes: max_staging_bytes,
          max_plaintext_bytes: max_plaintext_bytes,
          max_envelope_bytes: max_envelope_bytes
        )
        section_bytes = read_exact(input, Format.section_length(header))
        section = Format.parse_section(section_bytes, 0, header)
        estimated_envelope =
          header.raw.bytesize + section.raw.bytesize + header.padded_inner_length + Format::TAG_BYTES
        Format.check_resource_limits!(
          padded_inner_length: header.padded_inner_length,
          envelope_bytes: estimated_envelope,
          max_staging_bytes: max_staging_bytes,
          max_plaintext_bytes: max_plaintext_bytes,
          max_envelope_bytes: max_envelope_bytes
        )
        dek = Seal.send(:unwrap_dek, header, section, with)
        decryptor = Native::Decryptor.new(dek, header.payload_nonce, Native.sha256(header.raw))
        remaining = header.padded_inner_length
        while remaining.positive?
          take = [remaining, chunk_size].min
          chunk = read_exact(input, take)
          staging.write(decryptor.update(chunk))
          remaining -= take
        end
        tag = read_exact(input, Format::TAG_BYTES)
        if strict_eof
          raise FormatError, "trailing bytes after envelope" unless input.read(1).nil?
        end
        decryptor.final(tag)
        { header: header, section: section }
      ensure
        Seal.send(:wipe_string!, dek) if defined?(dek)
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
          Seal.send(:wipe_string!, random)
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

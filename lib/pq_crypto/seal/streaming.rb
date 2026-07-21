# frozen_string_literal: true

module PQCrypto
  module Seal
    class StreamingEncryptor
      def initialize(input, output, size:, to:, metadata:, public_metadata:,
                     recipient_capacity:, slot_size:, padding:, chunk_size:, strict_size:)
        @input = input
        @output = output
        @content_size = Integer(size)
        raise ArgumentError, "size must be non-negative" if @content_size.negative?

        @metadata = String(metadata).b
        raise InvalidConfigurationError, "private metadata is too large" if @metadata.bytesize > Format::MAX_PRIVATE_METADATA_BYTES

        @recipients = KeyMaterial.public_keys(to)
        @capacity = Format.validate_capacity!(recipient_capacity, @recipients.length)
        @slot_size = Format.validate_slot_size!(slot_size)
        @public_metadata = public_metadata
        @padding = padding
        @chunk_size = IOHelpers.validate_chunk_size(chunk_size)
        @strict_size = strict_size
      end

      def call
        plan = build_plan
        encryptor = Native::Encryptor.new(plan.dek, plan.payload_nonce, plan.header_hash)
        write_parts(plan.header, plan.section)
        write_encrypted(encryptor, plan.inner_prefix)
        write_encrypted(encryptor, @metadata)
        encrypt_content(encryptor)
        verify_declared_size!
        encrypt_padding(encryptor, plan.padding_length)
        write_parts(encryptor.final)
        @output
      ensure
        plan.wipe! if plan
        Secrets.wipe!(@metadata)
      end

      private

      def build_plan
        EncryptionPlan.build(
          recipients: @recipients,
          capacity: @capacity,
          slot_size: @slot_size,
          padding: @padding,
          public_metadata: @public_metadata,
          content_size: @content_size,
          metadata_size: @metadata.bytesize
        )
      end

      def encrypt_content(encryptor)
        message = { message: "input ended before declared size" }
        IOHelpers.each_exact_chunk(@input, @content_size, @chunk_size, **message) do |chunk|
          write_encrypted(encryptor, chunk)
        ensure
          Secrets.wipe!(chunk)
        end
      end

      def verify_declared_size!
        return unless @strict_size

        raise ArgumentError, "input contains more bytes than declared size" unless @input.read(1).nil?
      end

      def encrypt_padding(encryptor, length)
        remaining = length
        while remaining.positive?
          bytes = nil
          begin
            bytes = Native.random_bytes([remaining, @chunk_size].min)
            write_encrypted(encryptor, bytes)
            remaining -= bytes.bytesize
          ensure
            Secrets.wipe!(bytes)
          end
        end
      end

      def write_encrypted(encryptor, plaintext)
        return if plaintext.empty?

        write_parts(encryptor.update(plaintext))
      end

      def write_parts(*parts)
        parts.each { |part| IOHelpers.write_all(@output, part) unless part.empty? }
      end
    end

    class StagedInner
      attr_reader :content_offset, :content_length, :metadata, :padding_bytes

      def self.parse(staging, expected_size)
        raise FormatError, "staging size mismatch" unless staging.stat.size == expected_size

        staging.rewind
        prefix = IOHelpers.read_exact(staging, Format::INNER_PREFIX_BYTES)
        reader = Binary::Reader.new(prefix)
        raise FormatError, "unsupported inner version" unless reader.u8 == Format::INNER_VERSION
        raise FormatError, "unknown inner flags" unless reader.u8 == Format::INNER_FLAGS

        content_length = reader.u64
        metadata_length = reader.u32
        raise FormatError, "private metadata is too large" if metadata_length > Format::MAX_PRIVATE_METADATA_BYTES

        minimum = Format::INNER_PREFIX_BYTES + metadata_length + content_length
        raise FormatError, "inner lengths exceed authenticated frame" if minimum > expected_size

        metadata = IOHelpers.read_exact(staging, metadata_length)
        new(
          content_offset: Format::INNER_PREFIX_BYTES + metadata_length,
          content_length: content_length,
          metadata: metadata,
          padding_bytes: expected_size - minimum
        )
      end

      def initialize(content_offset:, content_length:, metadata:, padding_bytes:)
        @content_offset = content_offset
        @content_length = content_length
        @metadata = metadata
        @padding_bytes = padding_bytes
      end
    end

    class VerifiedStream
      attr_reader :stream_envelope, :inner

      def initialize(staging, stream_envelope, inner, chunk_size)
        @staging = staging
        @stream_envelope = stream_envelope
        @inner = inner
        @chunk_size = chunk_size
      end

      def verify_padding!(required_padding)
        Padding.verify!(
          required_padding,
          header: stream_envelope.header,
          envelope_bytes: stream_envelope.envelope_bytes,
          content_bytes: inner.content_length,
          metadata_bytes: inner.metadata.bytesize
        )
        self
      end

      def publish_to(output)
        message = { message: "staging input is truncated" }
        @staging.seek(inner.content_offset, ::IO::SEEK_SET)
        IOHelpers.each_exact_chunk(@staging, inner.content_length, @chunk_size, **message) do |chunk|
          IOHelpers.write_all(output, chunk)
        ensure
          Secrets.wipe!(chunk)
        end

        self
      end

      def content_io
        @staging.seek(inner.content_offset, ::IO::SEEK_SET)
        @staging
      end

      def opened
        Opened.build(stream_envelope.header, stream_envelope.section, data: nil, metadata: inner.metadata)
      end

      def close!
        IOHelpers.close_tempfile(@staging)
      end
    end

    class AuthenticatedStaging
      def initialize(input, credentials:, staging_directory:, chunk_size:, strict_eof:, limits:)
        @input = input
        @credentials = credentials
        @staging_directory = staging_directory
        @chunk_size = IOHelpers.validate_chunk_size(chunk_size)
        @strict_eof = strict_eof
        @limits = limits
      end

      def call
        ciphertext_staging = IOHelpers.staging_file("pqcrypto-seal-ct", @staging_directory)
        envelope = StreamEnvelope.read(@input, @limits)
        dek = envelope.unwrap_dek(@credentials)
        tag = stage_and_authenticate_ciphertext(ciphertext_staging, envelope, dek)
        plaintext_staging = materialize_verified_plaintext(ciphertext_staging, envelope, dek, tag)
        IOHelpers.close_tempfile(ciphertext_staging)
        ciphertext_staging = nil
        inner = StagedInner.parse(plaintext_staging, envelope.header.padded_inner_length)
        @limits.check_plaintext!(inner.content_length)
        VerifiedStream.new(plaintext_staging, envelope, inner, @chunk_size)
      rescue StandardError
        Secrets.wipe!(inner.metadata) if inner
        IOHelpers.close_tempfile(plaintext_staging) if plaintext_staging
        IOHelpers.close_tempfile(ciphertext_staging) if ciphertext_staging
        raise
      ensure
        Secrets.wipe!(dek)
      end

      private

      def stage_and_authenticate_ciphertext(staging, envelope, dek)
        envelope.stream_verified_payload(@input, dek, @chunk_size, strict_eof: @strict_eof) do |ciphertext, _plaintext|
          IOHelpers.write_all(staging, ciphertext)
        end
      end

      def materialize_verified_plaintext(ciphertext_staging, envelope, dek, tag)
        staging = IOHelpers.staging_file("pqcrypto-seal-inner", @staging_directory)
        decryptor = Native::Decryptor.new(dek, envelope.header.payload_nonce, envelope.header_hash)
        ciphertext_staging.rewind
        message = { message: "staged ciphertext is truncated" }
        IOHelpers.each_exact_chunk(
          ciphertext_staging, envelope.header.padded_inner_length, @chunk_size, **message
        ) do |ciphertext|
          plaintext = decryptor.update(ciphertext)
          begin
            IOHelpers.write_all(staging, plaintext)
          ensure
            Secrets.wipe!(plaintext)
          end
        end
        decryptor.final(tag)
        staging.flush
        staging
      rescue StandardError
        IOHelpers.close_tempfile(staging) if staging
        raise
      end
    end

    class StreamingDecryptor
      def initialize(input, output, credentials:, staging_directory:, chunk_size:,
                     strict_eof:, required_padding:, limits:)
        @input = input
        @output = output
        @credentials = credentials
        @staging_directory = staging_directory
        @chunk_size = chunk_size
        @strict_eof = strict_eof
        @required_padding = required_padding
        @limits = limits
      end

      def call
        verified = AuthenticatedStaging.new(
          @input,
          credentials: @credentials,
          staging_directory: @staging_directory,
          chunk_size: @chunk_size,
          strict_eof: @strict_eof,
          limits: @limits
        ).call
        opened = verified.verify_padding!(@required_padding).publish_to(@output).opened
        opened
      ensure
        Secrets.wipe!(verified.inner.metadata) if verified && !opened
        verified.close! if verified
      end
    end
  end
end

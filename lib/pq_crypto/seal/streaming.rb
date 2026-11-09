# frozen_string_literal: true

module PQCrypto
  module Seal
    class SizedSource
      attr_reader :size, :chunk_size

      def initialize(input, options)
        @size = Integer(options.fetch(:size))
        raise ArgumentError, 'size must be non-negative' if size.negative?

        @chunk_size = IOHelpers.validate_chunk_size(options.fetch(:chunk_size))
        @reader = ExactReader.new(input, 'input ended before declared size')
        @strict = options.fetch(:strict_size)
      end

      def encrypt_into(writer)
        reader.each_chunk(size, chunk_size) { |chunk| writer.encrypt(chunk) }
        finish
      end

      private

      attr_reader :reader, :strict

      def finish
        return unless strict
        raise ArgumentError, 'input contains more bytes than declared size' unless reader.eof?
      end
    end

    class EncryptedWriter
      def initialize(output, encryptor)
        @output = output
        @encryptor = encryptor
      end

      def raw(*parts)
        parts.each { |part| IOHelpers.write_all(output, part) unless part.empty? }
      end

      def encrypt(plaintext)
        raw(encryptor.update(plaintext)) unless plaintext.empty?
      end

      def finish(padding_length, chunk_size)
        0.step(padding_length - 1, chunk_size) { |offset| encrypt_random([chunk_size, padding_length - offset].min) }
        raw(encryptor.final)
      end

      private

      attr_reader :output, :encryptor

      def encrypt_random(length)
        bytes = Native.random_bytes(length)
        encrypt(bytes)
      ensure
        Secrets.wipe!(bytes)
      end
    end

    class StreamingEncryptor
      def initialize(input, output, options)
        @source = SizedSource.new(input, options)
        @settings = EncryptionSettings.from_options(options)
        @metadata = PrivateMetadata.copy(options.fetch(:metadata))
        @output = output
      end

      def call
        plan = EncryptionPlan.build(settings, InnerFrame.new(source.size, metadata.bytesize))
        write_envelope(plan.writer(output), plan.padding_length)
        output
      ensure
        plan&.wipe
        Secrets.wipe!(metadata)
      end

      private

      attr_reader :source, :settings, :metadata, :output

      def write_envelope(writer, padding_length)
        writer.encrypt(metadata)
        source.encrypt_into(writer)
        writer.finish(padding_length, source.chunk_size)
      end
    end

    StagedInner = Struct.new(:content_offset, :content_length, :metadata, :padding_bytes, keyword_init: true) do
      class << self
        def parse(staging, expected_size)
          reader = rewound_reader(staging, expected_size)
          prefix = Binary::Reader.new(reader.read(Format::INNER_PREFIX_BYTES))
          content_length, metadata_length = Format::InnerCodec.parse_prefix(prefix)
          layout = layout(Format::INNER_PREFIX_BYTES + metadata_length, content_length, expected_size)
          new(metadata: reader.read(metadata_length), **layout)
        end

        def rewound_reader(staging, expected_size)
          Format::ValueCheck.new(expected_size, 'staging size mismatch').call(staging.stat.size)
          ExactReader.rewound(staging, 'truncated envelope', wipe_reads: true)
        end

        def layout(content_offset, content_length, expected_size)
          padding_bytes = expected_size - content_offset - content_length
          raise FormatError, 'inner lengths exceed authenticated frame' if padding_bytes.negative?

          { content_offset: content_offset, content_length: content_length, padding_bytes: padding_bytes }
        end
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

      def verify_padding(required_padding)
        verification = stream_envelope.padding_verification(inner.content_length, inner.metadata.bytesize)
        Padding.verify(required_padding, verification)
        self
      end

      def publish_to(output)
        reader = ExactReader.new(content_io, 'staging input is truncated', wipe_reads: true)
        reader.each_chunk(inner.content_length, chunk_size) { |chunk| IOHelpers.write_all(output, chunk) }
        self
      end

      def reencrypt_to(output, options)
        encryption = RotationOptions.new(stream_envelope, options).encryption(inner.metadata)
        streaming = { size: inner.content_length, chunk_size: chunk_size, strict_size: false }
        StreamingEncryptor.new(content_io, output, encryption.merge(streaming)).call
      end

      def opened
        Opened.build(stream_envelope.header, stream_envelope.section, data: nil, metadata: inner.metadata)
      end

      def close
        IOHelpers.close_tempfile(staging)
      end

      def discard
        Secrets.wipe!(inner&.metadata)
        close
      end

      private

      attr_reader :staging, :chunk_size

      def content_io
        staging.seek(inner.content_offset, ::IO::SEEK_SET)
        staging
      end
    end

    class PlaintextMaterializer
      def initialize(envelope, dek, chunk_size)
        @envelope = envelope
        @decryptor = envelope.payload_decryptor(dek)
        @chunk_size = chunk_size
      end

      def call(ciphertext, tag, directory)
        staging = IOHelpers.staging_file('pqcrypto-seal-inner', directory)
        complete = decrypt_into(ciphertext, staging, tag)
      ensure
        IOHelpers.close_tempfile(staging) unless complete
      end

      private

      attr_reader :envelope, :decryptor, :chunk_size

      def decrypt_into(ciphertext, staging, tag)
        reader = ExactReader.rewound(ciphertext, 'staged ciphertext is truncated')
        reader.each_chunk(envelope.header.padded_inner_length, chunk_size) do |chunk|
          IOHelpers.write_secret(staging, decryptor.update(chunk))
        end
        decryptor.final(tag)
        staging.tap(&:flush)
      end
    end

    class AuthenticatedStaging
      def initialize(input, options)
        @input = input
        @options = options
        @limits = options.fetch(:limits)
        @chunk_size = IOHelpers.validate_chunk_size(options.fetch(:chunk_size))
      end

      def call
        envelope = StreamEnvelope.read(input, limits)
        dek = envelope.unwrap_dek(options.fetch(:with))
        staging = staged_plaintext(envelope, dek)
        inner = StagedInner.parse(staging, envelope.header.padded_inner_length)
        limits.check_plaintext(inner.content_length)
        verified = VerifiedStream.new(staging, envelope, inner, chunk_size)
      ensure
        Secrets.wipe!(dek)
        unless verified
          Secrets.wipe!(inner&.metadata)
          IOHelpers.close_tempfile(staging)
        end
      end

      private

      attr_reader :input, :options, :limits, :chunk_size

      def staged_plaintext(envelope, dek)
        directory = options.fetch(:staging_directory)
        IOHelpers.with_tempfile('pqcrypto-seal-ct', directory) do |ciphertext|
          tag = AuthenticatedPass.new(envelope, dek, chunk_size).copy(input, ciphertext)
          check_trailing_bytes
          PlaintextMaterializer.new(envelope, dek, chunk_size).call(ciphertext, tag, directory)
        end
      end

      def check_trailing_bytes
        IOHelpers.ensure_eof(input, 'trailing bytes after envelope') if options.fetch(:strict_eof)
      end
    end

    class StreamingDecryptor
      def initialize(input, output, options)
        @input = input
        @output = output
        @options = options
      end

      def call
        verified = AuthenticatedStaging.new(@input, @options).call
        published = verified.verify_padding(@options.fetch(:required_padding)).publish_to(@output)
        opened = published.opened
      ensure
        opened ? verified.close : verified&.discard
      end
    end
  end
end

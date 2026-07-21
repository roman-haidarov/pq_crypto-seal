# frozen_string_literal: true

module PQCrypto
  module Seal
    class FileRecipientRebuilder
      def initialize(source, destination, credentials:, recipients:, chunk_size:, limits:)
        @source = source
        @destination = destination
        @credentials = credentials
        @recipients = KeyMaterial.public_keys(recipients)
        @chunk_size = IOHelpers.validate_chunk_size(chunk_size)
        @limits = limits
      end

      def call
        File.open(@source, "rb") do |input|
          envelope = StreamEnvelope.read(input, @limits)
          Format.validate_capacity!(envelope.header.recipient_capacity, @recipients.length)
          dek = envelope.unwrap_dek(@credentials)
          new_section = build_section(envelope, dek)
          AtomicDestination.new(@destination).write do |output|
            rewrite_verified(input, output, envelope, new_section, dek)
          end
        ensure
          Secrets.wipe!(dek)
        end

        @destination
      end

      private

      def build_section(envelope, dek)
        RecipientSectionBuilder.new(
          recipients: @recipients,
          capacity: envelope.header.recipient_capacity,
          slot_size: envelope.header.slot_size,
          payload_id: envelope.header.payload_id,
          header_hash: envelope.header_hash,
          dek: dek
        ).call
      end

      def rewrite_verified(input, output, envelope, new_section, dek)
        IOHelpers.write_all(output, envelope.header.raw)
        IOHelpers.write_all(output, new_section)
        tag = envelope.stream_verified_payload(input, dek, @chunk_size) do |ciphertext, _plaintext|
          IOHelpers.write_all(output, ciphertext)
        end
        IOHelpers.write_all(output, tag)
      end
    end

    class FileDekRotator
      def initialize(source, destination, credentials:, recipients:, padding:,
                     staging_directory:, chunk_size:, limits:,
                     recipient_capacity: nil, slot_size: nil)
        @source = source
        @destination = destination
        @credentials = credentials
        @recipients = recipients
        @padding = padding
        @staging_directory = staging_directory
        @chunk_size = IOHelpers.validate_chunk_size(chunk_size)
        @limits = limits
        @recipient_capacity = recipient_capacity
        @slot_size = slot_size
      end

      def call
        File.open(@source, "rb") do |input|
          verified = AuthenticatedStaging.new(
            input,
            credentials: @credentials,
            staging_directory: @staging_directory,
            chunk_size: @chunk_size,
            strict_eof: true,
            limits: @limits
          ).call
          rotate(verified)
        ensure
          Secrets.wipe!(verified.inner.metadata) if verified
          verified.close! if verified
        end

        @destination
      end

      private

      def rotate(verified)
        envelope = verified.stream_envelope
        padding = @padding == :preserve ? { to: envelope.envelope_bytes } : @padding
        capacity = @recipient_capacity.nil? ? envelope.header.recipient_capacity : @recipient_capacity
        slot = @slot_size.nil? ? envelope.header.slot_size : @slot_size
        AtomicDestination.new(@destination).write do |output|
          StreamingEncryptor.new(
            verified.content_io,
            output,
            size: verified.inner.content_length,
            to: @recipients,
            metadata: verified.inner.metadata,
            public_metadata: envelope.header.public_metadata,
            recipient_capacity: capacity,
            slot_size: slot,
            padding: padding,
            chunk_size: @chunk_size,
            strict_size: false
          ).call
        end
      end
    end

    module FileOperations
      module_function

      def encrypt(source, destination, **options)
        File.open(source, "rb") do |input|
          AtomicDestination.new(destination).write do |output|
            StreamingEncryptor.new(input, output, size: input.stat.size, strict_size: true, **options).call
          end
        end

        destination
      end

      def decrypt(source, destination, credentials:, **options)
        File.open(source, "rb") do |input|
          AtomicDestination.new(destination).write do |output|
            StreamingDecryptor.new(input, output, credentials: credentials, strict_eof: true, **options).call
          end
        end

        destination
      end

      def inspect(source, limits:)
        File.open(source, "rb") do |input|
          envelope = StreamEnvelope.read(input, limits)
          raise FormatError, "file length does not match envelope" unless input.stat.size == envelope.envelope_bytes

          envelope.inspection
        end
      end
    end
  end
end

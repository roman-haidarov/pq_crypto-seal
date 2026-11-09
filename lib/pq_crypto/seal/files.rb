# frozen_string_literal: true

module PQCrypto
  module Seal
    FilePaths = Struct.new(:source, :destination) do
      def read_source(&block)
        File.open(source, 'rb', &block)
        destination
      end

      def write_destination(&block)
        AtomicDestination.new(destination).write(&block)
      end
    end

    class FileRecipientRebuilder
      def initialize(paths, options)
        @paths = paths
        @options = options
        @recipients = KeyMaterial.public_keys(options.fetch(:recipients))
        @chunk_size = IOHelpers.validate_chunk_size(options.fetch(:chunk_size))
      end

      def call
        paths.read_source { |input| rebuild(input) }
      end

      private

      attr_reader :paths, :options, :recipients, :chunk_size

      def rebuild(input)
        envelope = read_envelope(input)
        dek = envelope.unwrap_dek(options.fetch(:with))
        publish(input, envelope, dek)
      ensure
        Secrets.wipe!(dek)
      end

      def read_envelope(input)
        envelope = StreamEnvelope.read(input, options.fetch(:limits))
        Format.validate_recipient_count!(envelope.header.recipient_capacity, recipients.length)
        envelope
      end

      def publish(input, envelope, dek)
        section = RecipientSectionBuilder.new(envelope.section_spec, recipients, dek).call
        pass = AuthenticatedPass.new(envelope, dek, chunk_size)
        paths.write_destination { |output| pass.rewrite(input, output, section) }
      end
    end

    class FileDekRotator
      def initialize(paths, options)
        @paths = paths
        @options = options.merge(strict_eof: true)
      end

      def call
        paths.read_source { |input| rotate_from(input) }
      end

      private

      attr_reader :paths, :options

      def rotate_from(input)
        verified = AuthenticatedStaging.new(input, options).call
        paths.write_destination { |output| verified.reencrypt_to(output, options) }
      ensure
        verified&.discard
      end
    end

    class FileOperation
      def initialize(paths, options)
        @paths = paths
        @options = options
      end

      def encrypt
        paths.read_source { |input| encrypt_stream(input) }
      end

      def decrypt
        paths.read_source { |input| decrypt_stream(input) }
      end

      private

      attr_reader :paths, :options

      def encrypt_stream(input)
        stream_options = options.merge(size: input.stat.size, strict_size: true)
        paths.write_destination { |output| StreamingEncryptor.new(input, output, stream_options).call }
      end

      def decrypt_stream(input)
        stream_options = options.merge(strict_eof: true)
        paths.write_destination { |output| StreamingDecryptor.new(input, output, stream_options).call }
      end
    end

    module FileInspection
      module_function

      def call(source, limits)
        File.open(source, 'rb') do |input|
          envelope = StreamEnvelope.read(input, limits)
          raise FormatError, 'file length does not match envelope' unless input.stat.size == envelope.envelope_bytes

          envelope.inspection
        end
      end
    end
  end
end

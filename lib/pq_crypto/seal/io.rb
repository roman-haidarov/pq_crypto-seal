# frozen_string_literal: true

module PQCrypto
  module Seal
    module IOAPI
      DEFAULT_CHUNK_SIZE = 1024 * 1024
      FILE_ENCRYPTION_OPTIONS = OptionSchema.new(
        required: %i[to],
        defaults: {
          metadata: ''.b.freeze, public_metadata: ''.b.freeze, padding: :padme,
          recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
          slot_size: Format::DEFAULT_SLOT_SIZE, chunk_size: DEFAULT_CHUNK_SIZE
        }
      )
      private_constant :FILE_ENCRYPTION_OPTIONS

      module_function

      def encrypt_io(input, output, size:, to:, metadata: ''.b, public_metadata: ''.b,
                     recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                     slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme,
                     chunk_size: DEFAULT_CHUNK_SIZE, strict_size: true)
        options = {
          size: size, to: to, metadata: metadata, public_metadata: public_metadata,
          recipient_capacity: recipient_capacity, slot_size: slot_size, padding: padding,
          chunk_size: chunk_size, strict_size: strict_size
        }
        StreamingEncryptor.new(input, output, options).call
      end

      def decrypt_io(input, output, with:, staging_directory: nil,
                     chunk_size: DEFAULT_CHUNK_SIZE, strict_eof: true,
                     required_padding: :from_header, **limit_options)
        options = {
          with: with, staging_directory: staging_directory, chunk_size: chunk_size, strict_eof: strict_eof,
          required_padding: required_padding, limits: ResourceLimits.resolve(limit_options)
        }
        StreamingDecryptor.new(input, output, options).call
      end

      def encrypt_frame_io(input, output, size:, to:, **options)
        encrypt_io(input, output, size: size, to: to, strict_size: false, **options)
      end

      def decrypt_frame_io(input, output, with:, **options)
        decrypt_io(input, output, with: with, strict_eof: false, **options)
      end

      def encrypt_file(source, destination, **options)
        FileOperation.new(FilePaths.new(source, destination), FILE_ENCRYPTION_OPTIONS.resolve(options)).encrypt
      end

      def decrypt_file(source, destination, with:, staging_directory: nil,
                       chunk_size: DEFAULT_CHUNK_SIZE, required_padding: :from_header, **limit_options)
        options = {
          with: with, staging_directory: staging_directory, chunk_size: chunk_size,
          required_padding: required_padding, limits: ResourceLimits.resolve(limit_options)
        }
        FileOperation.new(FilePaths.new(source, destination), options).decrypt
      end

      def rebuild_recipients_file(source, destination, with:, recipients:,
                                  chunk_size: DEFAULT_CHUNK_SIZE, **limit_options)
        options = {
          with: with, recipients: recipients, chunk_size: chunk_size, limits: ResourceLimits.resolve(limit_options)
        }
        FileRecipientRebuilder.new(FilePaths.new(source, destination), options).call
      end

      def add_recipient_file(source, destination, with:, recipient:, current_recipients:, **options)
        rebuild_recipients_file(
          source, destination, with: with, recipients: Array(current_recipients) + [recipient], **options
        )
      end

      def rotate_dek_file(source, destination, with:, recipients:,
                          padding: :preserve, staging_directory: nil, chunk_size: DEFAULT_CHUNK_SIZE,
                          recipient_capacity: nil, slot_size: nil, **limit_options)
        options = {
          with: with, recipients: recipients, padding: padding, staging_directory: staging_directory,
          chunk_size: chunk_size, recipient_capacity: recipient_capacity, slot_size: slot_size,
          limits: ResourceLimits.resolve(limit_options)
        }
        FileDekRotator.new(FilePaths.new(source, destination), options).call
      end

      def inspect_file(source, **limit_options)
        FileInspection.call(source, ResourceLimits.resolve(limit_options))
      end
    end
  end
end

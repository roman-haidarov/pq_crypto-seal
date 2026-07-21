# frozen_string_literal: true

module PQCrypto
  module Seal
    module IOAPI
      DEFAULT_CHUNK_SIZE = 1024 * 1024

      module_function

      def encrypt_io(input, output, size:, to:, metadata: "".b, public_metadata: "".b,
                     recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                     slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme,
                     chunk_size: DEFAULT_CHUNK_SIZE, strict_size: true)
        StreamingEncryptor.new(
          input,
          output,
          size: size,
          to: to,
          metadata: metadata,
          public_metadata: public_metadata,
          recipient_capacity: recipient_capacity,
          slot_size: slot_size,
          padding: padding,
          chunk_size: chunk_size,
          strict_size: strict_size
        ).call
      end

      def decrypt_io(input, output, with:, staging_directory: nil,
                     chunk_size: DEFAULT_CHUNK_SIZE, strict_eof: true,
                     required_padding: :from_header, **limit_options)
        StreamingDecryptor.new(
          input,
          output,
          credentials: with,
          staging_directory: staging_directory,
          chunk_size: chunk_size,
          strict_eof: strict_eof,
          required_padding: required_padding,
          limits: ResourceLimits.resolve(limit_options)
        ).call
      end

      def encrypt_frame_io(input, output, size:, to:, **options)
        encrypt_io(input, output, size: size, to: to, strict_size: false, **options)
      end

      def decrypt_frame_io(input, output, with:, **options)
        decrypt_io(input, output, with: with, strict_eof: false, **options)
      end

      def encrypt_file(source, destination, **options)
        options = encryption_file_options(options)
        FileOperations.encrypt(source, destination, **options)
      end

      def decrypt_file(source, destination, with:, staging_directory: nil,
                       chunk_size: DEFAULT_CHUNK_SIZE, required_padding: :from_header,
                       **limit_options)
        FileOperations.decrypt(
          source,
          destination,
          credentials: with,
          staging_directory: staging_directory,
          chunk_size: chunk_size,
          required_padding: required_padding,
          limits: ResourceLimits.resolve(limit_options)
        )
      end

      def rebuild_recipients_file(source, destination, with:, recipients:,
                                  chunk_size: DEFAULT_CHUNK_SIZE, **limit_options)
        FileRecipientRebuilder.new(
          source,
          destination,
          credentials: with,
          recipients: recipients,
          chunk_size: chunk_size,
          limits: ResourceLimits.resolve(limit_options)
        ).call
      end

      def add_recipient_file(source, destination, with:, recipient:, current_recipients:, **options)
        rebuild_recipients_file(
          source,
          destination,
          with: with,
          recipients: Array(current_recipients) + [recipient],
          **options
        )
      end

      def rotate_dek_file(source, destination, with:, recipients:,
                          padding: :preserve, staging_directory: nil,
                          chunk_size: DEFAULT_CHUNK_SIZE,
                          recipient_capacity: nil, slot_size: nil, **limit_options)
        FileDekRotator.new(
          source,
          destination,
          credentials: with,
          recipients: recipients,
          padding: padding,
          staging_directory: staging_directory,
          chunk_size: chunk_size,
          recipient_capacity: recipient_capacity,
          slot_size: slot_size,
          limits: ResourceLimits.resolve(limit_options)
        ).call
      end

      def inspect_file(source, **limit_options)
        FileOperations.inspect(source, limits: ResourceLimits.resolve(limit_options))
      end

      def encryption_file_options(options)
        defaults = {
          metadata: "".b,
          public_metadata: "".b,
          recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
          slot_size: Format::DEFAULT_SLOT_SIZE,
          padding: :padme,
          chunk_size: DEFAULT_CHUNK_SIZE
        }
        defaults.merge(options)
      end

      private_class_method :encryption_file_options
    end
  end
end

# frozen_string_literal: true

module PQCrypto
  module Seal
    module PrivateMetadata
      module_function

      def copy(value)
        source = String(value)
        return source.unpack1('a*') if source.bytesize <= Format::MAX_PRIVATE_METADATA_BYTES

        raise InvalidConfigurationError, 'private metadata is too large'
      end
    end

    class OneShotEncryptor
      def initialize(data, options)
        @data = data
        @options = options
      end

      def call
        plaintext = String(@data).unpack1('a*')
        metadata = PrivateMetadata.copy(@options.fetch(:metadata))
        settings = EncryptionSettings.from_options(@options)
        plan = EncryptionPlan.build(settings, InnerFrame.new(plaintext.bytesize, metadata.bytesize))
        plan.envelope(metadata, plaintext)
      ensure
        plan&.wipe
        Secrets.wipe_each!(metadata, plaintext)
      end
    end

    class OneShotOpener
      def initialize(envelope, options)
        @limits = options.fetch(:limits)
        @envelope = Envelope.parse(envelope, limits: limits)
        @credentials = options.fetch(:with)
        @required_padding = options.fetch(:required_padding)
      end

      def call
        inner = envelope.open_inner(credentials)
        opened = build_opened(inner)
      ensure
        inner&.wipe unless opened
      end

      private

      attr_reader :envelope, :credentials, :limits, :required_padding

      def build_opened(inner)
        content = inner.content
        metadata = inner.metadata
        content_bytes = limits.check_plaintext(content.bytesize)
        Padding.verify(required_padding, envelope.padding_verification(content_bytes, metadata.bytesize))
        Opened.build(envelope.header, envelope.section, data: content, metadata: metadata)
      end
    end

    class RecipientRebuilder
      def initialize(envelope, options)
        @envelope = Envelope.parse(envelope, limits: options.fetch(:limits))
        @credentials = options.fetch(:with)
        @recipients = KeyMaterial.public_keys(options.fetch(:recipients))
      end

      def call
        Format.validate_recipient_count!(envelope.header.recipient_capacity, recipients.length)
        dek = envelope.unwrap_dek(credentials)
        envelope.verify_payload(dek)
        envelope.replace_section(RecipientSectionBuilder.new(envelope.section_spec, recipients, dek).call)
      ensure
        Secrets.wipe!(dek)
      end

      private

      attr_reader :envelope, :credentials, :recipients
    end

    class DekRotator
      def initialize(envelope, options)
        @limits = options.fetch(:limits)
        @envelope = Envelope.parse(envelope, limits: limits)
        @options = options
      end

      def call
        inner = envelope.open_inner(options.fetch(:with))
        reencrypt(inner)
      ensure
        inner&.wipe
      end

      private

      attr_reader :envelope, :limits, :options

      def reencrypt(inner)
        content = inner.content
        limits.check_plaintext(content.bytesize)
        OneShotEncryptor.new(content, RotationOptions.new(envelope, options).encryption(inner.metadata)).call
      end
    end

    class RotationOptions
      def initialize(source, options)
        @source = source
        @options = options
      end

      def encryption(metadata)
        header = source.header
        {
          to: options.fetch(:recipients), metadata: metadata, public_metadata: header.public_metadata,
          recipient_capacity: override(:recipient_capacity, header.recipient_capacity),
          slot_size: override(:slot_size, header.slot_size), padding: padding
        }
      end

      private

      attr_reader :source, :options

      def override(name, inherited)
        requested = options.fetch(name)
        requested.nil? ? inherited : requested
      end

      def padding
        requested = options.fetch(:padding)
        requested == :preserve ? { to: source.envelope_bytes } : requested
      end
    end

    module_function

    def credentials(secret_key:, public_key:)
      KeyMaterial.build_credentials(secret_key: secret_key, public_key: public_key)
    end

    def encrypt(data, to:, metadata: ''.b, public_metadata: ''.b,
                recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme)
      options = {
        to: to, metadata: metadata, public_metadata: public_metadata,
        recipient_capacity: recipient_capacity, slot_size: slot_size, padding: padding
      }
      OneShotEncryptor.new(data, options).call
    end

    def decrypt(envelope, with:, required_padding: :from_header, **limit_options)
      open(envelope, with: with, required_padding: required_padding, **limit_options).data
    end

    def open(envelope, with:, required_padding: :from_header, **limit_options)
      options = { with: with, required_padding: required_padding, limits: ResourceLimits.resolve(limit_options) }
      OneShotOpener.new(envelope, options).call
    end

    def inspect_envelope(envelope, **limit_options)
      Envelope.parse(envelope, limits: ResourceLimits.resolve(limit_options)).inspection
    end

    def digest(envelope)
      Native.sha256(String(envelope))
    end

    def rebuild_recipients(envelope, with:, recipients:, **limit_options)
      options = { with: with, recipients: recipients, limits: ResourceLimits.resolve(limit_options) }
      RecipientRebuilder.new(envelope, options).call
    end

    def add_recipient(envelope, with:, recipient:, current_recipients:, **limit_options)
      rebuild_recipients(envelope, with: with, recipients: Array(current_recipients) + [recipient], **limit_options)
    end

    def rotate_dek(envelope, with:, recipients:, padding: :preserve,
                   recipient_capacity: nil, slot_size: nil, **limit_options)
      options = {
        with: with, recipients: recipients, padding: padding, recipient_capacity: recipient_capacity,
        slot_size: slot_size, limits: ResourceLimits.resolve(limit_options)
      }
      DekRotator.new(envelope, options).call
    end
  end
end

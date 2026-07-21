# frozen_string_literal: true

module PQCrypto
  module Seal
    class OneShotEncryptor
      def initialize(data, to:, metadata:, public_metadata:, recipient_capacity:, slot_size:, padding:)
        @data = String(data).b
        @metadata = String(metadata).b
        validate_metadata!
        @recipients = KeyMaterial.public_keys(to)
        @capacity = Format.validate_capacity!(recipient_capacity, @recipients.length)
        @slot_size = Format.validate_slot_size!(slot_size)
        @public_metadata = public_metadata
        @padding = padding
      end

      def call
        plan = EncryptionPlan.build(
          recipients: @recipients,
          capacity: @capacity,
          slot_size: @slot_size,
          padding: @padding,
          public_metadata: @public_metadata,
          content_size: @data.bytesize,
          metadata_size: @metadata.bytesize
        )
        padding = Native.random_bytes(plan.padding_length)
        inner = plan.inner_prefix + @metadata + @data + padding
        ciphertext, tag = Native.aegis256_encrypt(
          plan.dek, plan.payload_nonce, plan.header_hash, inner
        )
        plan.header + plan.section + ciphertext + tag
      ensure
        plan.wipe! if plan
        Secrets.wipe_each!(inner, padding, @metadata, @data)
      end

      private

      def validate_metadata!
        return if @metadata.bytesize <= Format::MAX_PRIVATE_METADATA_BYTES

        raise InvalidConfigurationError, "private metadata is too large"
      end
    end

    class OneShotOpener
      def initialize(envelope, credentials:, required_padding:, limits:)
        @envelope = Envelope.parse(envelope, limits: limits)
        @credentials = credentials
        @required_padding = required_padding
        @limits = limits
      end

      def call
        dek = @envelope.unwrap_dek(@credentials)
        inner_bytes = @envelope.decrypt_inner(dek)
        inner = Format::InnerCodec.parse(inner_bytes)
        enforce_plaintext_limit!(inner)
        Padding.verify!(
          @required_padding,
          header: @envelope.header,
          envelope_bytes: @envelope.size,
          content_bytes: inner.content.bytesize,
          metadata_bytes: inner.metadata.bytesize
        )
        opened = Opened.build(
          @envelope.header,
          @envelope.section,
          data: inner.content,
          metadata: inner.metadata
        )
        opened
      ensure
        Secrets.wipe_each!(dek, inner_bytes)
        Secrets.wipe_each!(inner.content, inner.metadata) if inner && !opened
      end

      private

      def enforce_plaintext_limit!(inner)
        @limits.check_plaintext!(inner.content.bytesize)
      rescue ResourceLimitError
        Secrets.wipe_each!(inner.content, inner.metadata)
        raise
      end
    end

    class RecipientRebuilder
      def initialize(envelope, credentials:, recipients:, limits:)
        @envelope = Envelope.parse(envelope, limits: limits)
        @credentials = credentials
        @recipients = KeyMaterial.public_keys(recipients)
      end

      def call
        Format.validate_capacity!(@envelope.header.recipient_capacity, @recipients.length)
        dek = @envelope.unwrap_dek(@credentials)
        @envelope.verify_payload!(dek)
        @envelope.replace_section(build_section(dek))
      ensure
        Secrets.wipe!(dek)
      end

      private

      def build_section(dek)
        RecipientSectionBuilder.new(
          recipients: @recipients,
          capacity: @envelope.header.recipient_capacity,
          slot_size: @envelope.header.slot_size,
          payload_id: @envelope.header.payload_id,
          header_hash: @envelope.header_hash,
          dek: dek
        ).call
      end
    end

    class DekRotator
      def initialize(envelope, credentials:, recipients:, padding:, limits:,
                     recipient_capacity: nil, slot_size: nil)
        @envelope = Envelope.parse(envelope, limits: limits)
        @credentials = credentials
        @recipients = recipients
        @padding = padding == :preserve ? { to: @envelope.size } : padding
        @limits = limits
        @recipient_capacity = recipient_capacity
        @slot_size = slot_size
      end

      def call
        dek = @envelope.unwrap_dek(@credentials)
        inner_bytes = @envelope.decrypt_inner(dek)
        inner = Format::InnerCodec.parse(inner_bytes)
        @limits.check_plaintext!(inner.content.bytesize)
        OneShotEncryptor.new(
          inner.content,
          to: @recipients,
          metadata: inner.metadata,
          public_metadata: @envelope.header.public_metadata,
          recipient_capacity: capacity_for_reencrypt,
          slot_size: slot_size_for_reencrypt,
          padding: @padding
        ).call
      ensure
        Secrets.wipe_each!(dek, inner_bytes)
        Secrets.wipe_each!(inner.content, inner.metadata) if inner
      end

      private

      def capacity_for_reencrypt
        return @envelope.header.recipient_capacity if @recipient_capacity.nil?

        Format.validate_capacity!(@recipient_capacity, KeyMaterial.public_keys(@recipients).length)
      end

      def slot_size_for_reencrypt
        return @envelope.header.slot_size if @slot_size.nil?

        Format.validate_slot_size!(@slot_size)
      end
    end

    module_function

    def credentials(secret_key:, public_key:)
      KeyMaterial.build_credentials(secret_key: secret_key, public_key: public_key)
    end

    def encrypt(data, to:, metadata: "".b, public_metadata: "".b,
                recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme)
      OneShotEncryptor.new(
        data,
        to: to,
        metadata: metadata,
        public_metadata: public_metadata,
        recipient_capacity: recipient_capacity,
        slot_size: slot_size,
        padding: padding
      ).call
    end

    def decrypt(envelope, with:, required_padding: :from_header, **limit_options)
      open(envelope, with: with, required_padding: required_padding, **limit_options).data
    end

    def open(envelope, with:, required_padding: :from_header, **limit_options)
      OneShotOpener.new(
        envelope,
        credentials: with,
        required_padding: required_padding,
        limits: ResourceLimits.resolve(limit_options)
      ).call
    end

    def inspect_envelope(envelope, **limit_options)
      Envelope.parse(envelope, limits: ResourceLimits.resolve(limit_options)).inspection
    end

    def digest(envelope)
      Native.sha256(String(envelope).b)
    end

    def rebuild_recipients(envelope, with:, recipients:, **limit_options)
      RecipientRebuilder.new(
        envelope,
        credentials: with,
        recipients: recipients,
        limits: ResourceLimits.resolve(limit_options)
      ).call
    end

    def add_recipient(envelope, with:, recipient:, current_recipients:, **limit_options)
      rebuild_recipients(
        envelope,
        with: with,
        recipients: Array(current_recipients) + [recipient],
        **limit_options
      )
    end

    def rotate_dek(envelope, with:, recipients:, padding: :preserve,
                   recipient_capacity: nil, slot_size: nil, **limit_options)
      DekRotator.new(
        envelope,
        credentials: with,
        recipients: recipients,
        padding: padding,
        recipient_capacity: recipient_capacity,
        slot_size: slot_size,
        limits: ResourceLimits.resolve(limit_options)
      ).call
    end

    def parse_envelope(bytes)
      envelope = Envelope.parse(bytes)
      [envelope.header, envelope.section, envelope.ciphertext, envelope.tag]
    end

    def unwrap_dek(header, section, credentials)
      RecipientSectionOpener.new(header, section, credentials).call
    end

    def build_recipient_section(**options)
      RecipientSectionBuilder.new(**options).call
    end

    def wipe_string!(value)
      Secrets.wipe!(value)
    end

    PUBLIC_API = %i[
      credentials encrypt decrypt open inspect_envelope digest
      rebuild_recipients add_recipient rotate_dek
    ].freeze

    private_class_method(*(singleton_methods(false).map(&:to_sym) - PUBLIC_API))
  end
end

# frozen_string_literal: true

module PQCrypto
  module Seal
    module EnvelopeParts
      def unwrap_dek(credentials)
        RecipientSectionOpener.new(header, section, credentials).call
      end

      def section_spec
        SectionSpec.for_header(header, header_hash)
      end

      def payload_decryptor(dek)
        Native::Decryptor.new(dek, header.payload_nonce, header_hash)
      end

      def inspection
        Inspection.build(header, section, envelope_bytes: envelope_bytes)
      end

      def padding_verification(content_bytes, metadata_bytes)
        Padding::Verification.new(
          header: header, envelope_bytes: envelope_bytes,
          content_bytes: content_bytes, metadata_bytes: metadata_bytes
        )
      end
    end

    class Envelope
      include EnvelopeParts

      attr_reader :bytes, :header, :section, :header_hash

      def self.parse(value, limits: ResourceLimits.resolve)
        bytes = String(value).b
        limits.check_envelope(bytes.bytesize)
        new(bytes, Format.parse_header(bytes)).check_declared_size(limits)
      end

      def initialize(bytes, header)
        raw = header.raw
        @bytes = bytes
        @header = header
        @section = Format.parse_section(bytes, raw.bytesize, header)
        @header_hash = Native.sha256(raw)
      end

      def envelope_bytes
        bytes.bytesize
      end

      def check_declared_size(limits)
        declared = payload_offset + header.padded_inner_length + Format::TAG_BYTES
        raise FormatError, 'envelope length does not match header' unless envelope_bytes == declared

        limits.check_declared(header, declared)
        self
      end

      def ciphertext
        bytes.byteslice(payload_offset, header.padded_inner_length)
      end

      def tag
        bytes.byteslice(envelope_bytes - Format::TAG_BYTES, Format::TAG_BYTES)
      end

      def decrypt_inner(dek)
        Native.aegis256_decrypt(dek, header.payload_nonce, header_hash, ciphertext, tag)
      end

      def open_inner(credentials)
        dek = unwrap_dek(credentials)
        inner_bytes = decrypt_inner(dek)
        Format::InnerCodec.parse(inner_bytes)
      ensure
        Secrets.wipe_each!(dek, inner_bytes)
      end

      def verify_payload(dek)
        Secrets.wipe!(decrypt_inner(dek))
        self
      end

      def replace_section(new_section)
        header.raw + new_section + ciphertext + tag
      end

      private

      def payload_offset
        header.raw.bytesize + section.raw.bytesize
      end
    end

    PayloadIdentity = Struct.new(:payload_id, :payload_nonce, :dek) do
      def self.generate
        new(
          Native.random_bytes(Format::PAYLOAD_ID_BYTES),
          Native.random_bytes(Format::NONCE_BYTES),
          Native.random_bytes(Format::DEK_BYTES)
        )
      end
    end

    InnerFrame = Struct.new(:content_size, :metadata_size) do
      def prefix
        Format.inner_prefix(content_size, metadata_size)
      end

      def raw_length
        Format::INNER_PREFIX_BYTES + metadata_size + content_size
      end
    end

    EncryptionSettings = Struct.new(:recipients, :capacity, :slot_size, :padding, :public_metadata,
                                    keyword_init: true) do
      def self.from_options(options)
        recipients = KeyMaterial.public_keys(options.fetch(:to))
        capacity = Format.validate_capacity!(options.fetch(:recipient_capacity))
        new(
          recipients: recipients, capacity: Format.validate_recipient_count!(capacity, recipients.length),
          slot_size: Format.validate_slot_size!(options.fetch(:slot_size)),
          padding: Padding.for_encryption(options.fetch(:padding)),
          public_metadata: String(options.fetch(:public_metadata)).b
        )
      end

      def header(identity, inner_length)
        Format.build_header(
          payload_id: identity.payload_id, payload_nonce: identity.payload_nonce,
          recipient_capacity: capacity, slot_size: slot_size, padded_inner_length: inner_length,
          public_metadata: public_metadata, padding_policy_id: padding.id
        )
      end

      def framed_header(identity, raw_length)
        padded = padded_inner_length(identity, raw_length)
        [header(identity, padded), padded - raw_length]
      end

      def padded_inner_length(identity, raw_length)
        fixed = header(identity, raw_length).bytesize + Format.section_length_for(capacity, slot_size) +
                Format::TAG_BYTES
        padded = padding.target(fixed + raw_length) - fixed
        raise InvalidConfigurationError, 'invalid padding target' if padded < raw_length

        padded
      end

      def section(identity, header_hash)
        spec = SectionSpec.new(
          capacity: capacity, slot_size: slot_size, payload_id: identity.payload_id, header_hash: header_hash
        )
        RecipientSectionBuilder.new(spec, recipients, identity.dek).call
      end
    end

    Plan = Struct.new(:header, :section, :dek, :payload_nonce, :header_hash, :inner_prefix, :padding_length,
                      keyword_init: true) do
      def envelope(metadata, content)
        inner = inner_frame(metadata, content)
        header + section + Native.aegis256_encrypt(dek, payload_nonce, header_hash, inner).join
      ensure
        Secrets.wipe!(inner)
      end

      def writer(output)
        EncryptedWriter.new(output, Native::Encryptor.new(dek, payload_nonce, header_hash)).tap do |writer|
          writer.raw(header, section)
          writer.encrypt(inner_prefix)
        end
      end

      def wipe
        Secrets.wipe!(dek)
      end

      private

      def inner_frame(metadata, content)
        padding = Native.random_bytes(padding_length)
        parts = [inner_prefix, metadata, Binary.view(content), padding]
        frame = String.new(capacity: parts.sum(&:bytesize))
        built = parts.each_with_object(frame) { |part, buffer| buffer << part }
      ensure
        Secrets.wipe!(frame) unless built
        Secrets.wipe!(padding)
      end
    end

    class EncryptionPlan
      def self.build(settings, frame)
        new(settings, frame).build
      end

      def initialize(settings, frame)
        @settings = settings
        @frame = frame
        @identity = PayloadIdentity.generate
      end

      def build
        header, padding_length = settings.framed_header(identity, frame.raw_length)
        built = plan(header, Native.sha256(header), padding_length)
      ensure
        Secrets.wipe!(identity.dek) unless built
      end

      private

      attr_reader :settings, :frame, :identity

      def plan(header, header_hash, padding_length)
        Plan.new(
          header: header, header_hash: header_hash, dek: identity.dek, payload_nonce: identity.payload_nonce,
          inner_prefix: frame.prefix, padding_length: padding_length,
          section: settings.section(identity, header_hash)
        )
      end
    end
  end
end

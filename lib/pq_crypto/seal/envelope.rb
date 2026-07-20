# frozen_string_literal: true

module PQCrypto
  module Seal
    class Envelope
      attr_reader :bytes, :header, :section, :ciphertext, :tag

      def self.parse(value, limits: ResourceLimits.resolve)
        bytes = String(value).b
        limits.check_envelope!(bytes.bytesize)

        header = Format.parse_header(bytes)
        section_offset = header.raw.bytesize
        section = Format.parse_section(bytes, section_offset, header)
        payload_offset = section_offset + section.raw.bytesize
        expected_size = payload_offset + header.padded_inner_length + Format::TAG_BYTES
        raise FormatError, "envelope length does not match header" unless bytes.bytesize == expected_size

        limits.check_declared!(header, envelope_bytes: expected_size)

        new(
          bytes: bytes,
          header: header,
          section: section,
          ciphertext: bytes.byteslice(payload_offset, header.padded_inner_length).b,
          tag: bytes.byteslice(payload_offset + header.padded_inner_length, Format::TAG_BYTES).b
        )
      end

      def initialize(bytes:, header:, section:, ciphertext:, tag:)
        @bytes = bytes
        @header = header
        @section = section
        @ciphertext = ciphertext
        @tag = tag
      end

      def size
        bytes.bytesize
      end

      def header_hash
        @header_hash ||= Native.sha256(header.raw)
      end

      def unwrap_dek(credentials)
        RecipientSectionOpener.new(header, section, credentials).call
      end

      def decrypt_inner(dek)
        Native.aegis256_decrypt(dek, header.payload_nonce, header_hash, ciphertext, tag)
      end

      def verify_payload!(dek)
        verified = decrypt_inner(dek)
        true
      ensure
        Secrets.wipe!(verified)
      end

      def replace_section(new_section)
        header.raw + new_section + ciphertext + tag
      end

      def inspection
        Inspection.build(header, section, envelope_bytes: size)
      end
    end

    class EncryptionPlan
      attr_reader :header, :section, :dek, :payload_nonce, :header_hash,
                  :inner_prefix, :raw_inner_length, :padded_inner_length

      def self.build(**options)
        plan = new(**options)
        plan.build
        plan
      rescue StandardError
        plan.wipe! if plan
        raise
      end

      def initialize(recipients:, capacity:, slot_size:, padding:, public_metadata:,
                     content_size:, metadata_size:)
        @recipients = recipients
        @capacity = capacity
        @slot_size = slot_size
        @padding = Padding.for_encryption(padding)
        @public_metadata = public_metadata
        @content_size = Integer(content_size)
        @metadata_size = Integer(metadata_size)
      end

      def build
        materialize_secrets
        materialize_frame
        materialize_header
        materialize_section
        self
      end

      def padding_length
        padded_inner_length - raw_inner_length
      end

      def wipe!
        Secrets.wipe!(dek)
      end

      private

      def materialize_secrets
        @payload_id = Native.random_bytes(Format::PAYLOAD_ID_BYTES)
        @payload_nonce = Native.random_bytes(Format::NONCE_BYTES)
        @dek = Native.random_bytes(Format::DEK_BYTES)
      end

      def materialize_frame
        @inner_prefix = Format.inner_prefix(@content_size, @metadata_size)
        @raw_inner_length = inner_prefix.bytesize + @metadata_size + @content_size
      end

      def materialize_header
        placeholder = build_header(raw_inner_length)
        fixed_bytes = placeholder.bytesize + Format.section_length_for(@capacity, @slot_size) + Format::TAG_BYTES
        target = @padding.target(fixed_bytes + raw_inner_length)
        @padded_inner_length = target - fixed_bytes
        raise InvalidConfigurationError, "invalid padding target" if padded_inner_length < raw_inner_length

        @header = build_header(padded_inner_length)
        @header_hash = Native.sha256(header)
      end

      def materialize_section
        @section = RecipientSectionBuilder.new(
          recipients: @recipients,
          capacity: @capacity,
          slot_size: @slot_size,
          payload_id: @payload_id,
          header_hash: header_hash,
          dek: dek
        ).call
      end

      def build_header(inner_length)
        Format.build_header(
          payload_id: @payload_id,
          payload_nonce: payload_nonce,
          recipient_capacity: @capacity,
          slot_size: @slot_size,
          padded_inner_length: inner_length,
          public_metadata: @public_metadata,
          padding_policy_id: @padding.id
        )
      end
    end
  end
end

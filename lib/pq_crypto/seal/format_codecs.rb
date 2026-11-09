# frozen_string_literal: true

module PQCrypto
  module Seal
    module Format
      UIntField = Struct.new(:width) do
        def read(reader)
          reader.public_send(width)
        end

        def write(value)
          Binary.public_send(width, value)
        end
      end

      BytesField = Struct.new(:byte_length, :label) do
        def read(reader)
          reader.bytes(byte_length)
        end

        def write(value)
          bytes = String(value).b
          raise InvalidConfigurationError, "invalid #{label}" unless bytes.bytesize == byte_length

          bytes
        end
      end

      PrefixedBytesField = Struct.new(:limit, :label) do
        def read(reader)
          length = reader.u32
          raise FormatError, "#{label} is too large" if length > limit

          reader.bytes(length)
        end

        def write(value)
          bytes = String(value).b
          Binary.u32(writable_length(bytes)) + bytes
        end

        private

        def writable_length(bytes)
          length = bytes.bytesize
          return length if length <= limit

          raise InvalidConfigurationError, "#{label} is too large"
        end
      end

      HEADER_LAYOUT = {
        content_suite_id: UIntField.new(:u16),
        lookup_mode: UIntField.new(:u8),
        flags: UIntField.new(:u16),
        padding_policy_id: UIntField.new(:u8),
        payload_id: BytesField.new(PAYLOAD_ID_BYTES, 'payload_id'),
        payload_nonce: BytesField.new(NONCE_BYTES, 'payload nonce'),
        recipient_capacity: UIntField.new(:u16),
        slot_size: UIntField.new(:u16),
        padded_inner_length: UIntField.new(:u64),
        public_metadata: PrefixedBytesField.new(MAX_PUBLIC_METADATA_BYTES, 'public metadata')
      }.transform_values(&:freeze).freeze

      ACCEPT_FIELD = ->(value) { value }

      HEADER_CHECKS = {
        content_suite_id: SuiteCheck.new(CONTENT_SUITE_AEGIS256, 'content'),
        lookup_mode: SuiteCheck.new(LOOKUP_HINT, 'lookup mode'),
        flags: ValueCheck.new(FLAGS, 'unknown header flags'),
        padding_policy_id: ->(value) { Format.validate_padding_policy_id!(value, error: FormatError) },
        recipient_capacity: ->(value) { Format.validate_capacity!(value, error: FormatError) },
        slot_size: ->(value) { Format.validate_slot_size!(value, error: FormatError) },
        padded_inner_length: ->(value) { Format.validate_inner_length!(value) }
      }.transform_values(&:freeze).freeze

      module HeaderCodec
        FIXED_VALUES = {
          content_suite_id: Format::CONTENT_SUITE_AEGIS256,
          lookup_mode: Format::LOOKUP_HINT,
          flags: Format::FLAGS
        }.freeze
        BUILD_FIELDS = OptionSchema.new(required: Format::HEADER_LAYOUT.keys - FIXED_VALUES.keys)
        MAGIC_CHECK = Format::ValueCheck.new(Format::MAGIC, 'invalid envelope magic')

        module_function

        def build(attributes)
          values = FIXED_VALUES.merge(BUILD_FIELDS.resolve(attributes))
          Format.validate_padding_policy_id!(values.fetch(:padding_policy_id), error: InvalidConfigurationError)
          frame(Format::HEADER_LAYOUT.map { |name, field| field.write(values.fetch(name)) }.join)
        end

        def frame(body)
          length = Format::HEADER_PREFIX_BYTES + body.bytesize
          raise InvalidConfigurationError, 'header is too large' if length > Format::MAX_HEADER_BYTES

          Format::MAGIC + Binary.u8(Format::VERSION) + Binary.u32(length) + body
        end

        def parse(bytes)
          raw = Binary::Reader.new(bytes).bytes(declared_length(bytes))
          Format::Header.new(raw: raw, **read_fields(Binary::Reader.new(raw, Format::HEADER_PREFIX_BYTES)))
        end

        def declared_length(bytes)
          prefix = Binary::Reader.new(bytes)
          MAGIC_CHECK.call(prefix.bytes(Format::MAGIC.bytesize))
          version = prefix.u8
          raise FormatError, "unsupported format version #{version}" unless version == Format::VERSION

          Format.validate_header_length!(prefix.u32)
        end

        def read_fields(reader)
          fields = Format::HEADER_LAYOUT.to_h { |name, field| [name, read_field(reader, name, field)] }
          raise FormatError, 'non-canonical header length' unless reader.finished?

          fields
        end

        def read_field(reader, name, field)
          Format::HEADER_CHECKS.fetch(name, Format::ACCEPT_FIELD).call(field.read(reader))
        end
      end

      module SectionCodec
        SUITE_CHECK = Format::SuiteCheck.new(Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256, 'wrap suite')

        module_function

        def parse(bytes, offset, header)
          raw = Binary::Reader.new(bytes, offset).bytes(Format.section_length(header))
          reader = Binary::Reader.new(raw)
          Format::Section.new(
            wrap_suite_id: SUITE_CHECK.call(reader.u16), section_id: reader.bytes(Format::SECTION_ID_BYTES),
            raw: raw, slots_offset: Format::SECTION_PREFIX_BYTES,
            slots_length: raw.bytesize - Format::SECTION_PREFIX_BYTES
          )
        end
      end

      module InnerCodec
        VERSION_CHECK = Format::ValueCheck.new(Format::INNER_VERSION, 'unsupported inner version')
        FLAGS_CHECK = Format::ValueCheck.new(Format::INNER_FLAGS, 'unknown inner flags')

        module_function

        def prefix(content_length, metadata_length)
          Binary.u8(Format::INNER_VERSION) + Binary.u8(Format::INNER_FLAGS) +
            Binary.u64(content_length) + Binary.u32(metadata_length)
        end

        def parse(bytes)
          reader = Binary::Reader.new(bytes)
          content_length, metadata_length = parse_prefix(reader)
          metadata = reader.bytes(metadata_length)
          content = reader.bytes(content_length)
          Format::VerifiedInner.new(content: content, metadata: metadata, padding_bytes: reader.remaining)
        end

        def parse_prefix(reader)
          version, flags = reader.bytes(2).bytes
          VERSION_CHECK.call(version)
          FLAGS_CHECK.call(flags)
          [reader.u64, Format.validate_private_metadata_length!(reader.u32)]
        end
      end

      module_function

      def build_header(**attributes)
        HeaderCodec.build(attributes)
      end

      def parse_header(bytes)
        HeaderCodec.parse(bytes)
      end

      def parse_section(bytes, offset, header)
        SectionCodec.parse(bytes, offset, header)
      end

      def split_slot(slot)
        reader = Binary::Reader.new(slot)
        fields = SLOT_FIELDS.to_h { |name, length| [name, reader.bytes(length)] }
        fields.merge(padding: reader.bytes(reader.remaining))
      end

      def inner_prefix(content_length, private_metadata_length)
        InnerCodec.prefix(content_length, private_metadata_length)
      end
    end
  end
end

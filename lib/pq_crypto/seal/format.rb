# frozen_string_literal: true

module PQCrypto
  module Seal
    module Format
      MAGIC = "PQCSEAL1".b
      VERSION = 1
      CONTENT_SUITE_AEGIS256 = 1
      WRAP_SUITE_MLKEM768_X25519_AEGIS256 = 1
      LOOKUP_HINT = 1
      FLAGS = 0
      INNER_VERSION = 1
      INNER_FLAGS = 0

      PADDING_NONE = 0
      PADDING_PADME = 1
      PADDING_FIXED = 2
      PADDING_BUCKETS = 3
      PADDING_POLICY_IDS = [PADDING_NONE, PADDING_PADME, PADDING_FIXED, PADDING_BUCKETS].freeze

      PAYLOAD_ID_BYTES = 32
      NONCE_BYTES = 32
      TAG_BYTES = 32
      HINT_BYTES = 32
      SECTION_ID_BYTES = 32

      XWING_PUBLIC_KEY_BYTES = 1216
      XWING_CIPHERTEXT_BYTES = 1120
      XWING_SHARED_SECRET_BYTES = 32

      DEK_BYTES = 32
      STANZA_BYTES = HINT_BYTES + XWING_CIPHERTEXT_BYTES + NONCE_BYTES + DEK_BYTES + TAG_BYTES
      DEFAULT_SLOT_SIZE = 2048
      MIN_SLOT_SIZE = 2048
      MAX_SLOT_SIZE = 8192
      SLOT_GRANULARITY = 256
      DEFAULT_RECIPIENT_CAPACITY = 4
      MAX_RECIPIENT_CAPACITY = 32
      MAX_PUBLIC_METADATA_BYTES = 1 * 1024 * 1024
      MAX_PRIVATE_METADATA_BYTES = 16 * 1024 * 1024
      MAX_HEADER_BYTES = 2 * 1024 * 1024

      DEFAULT_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
      DEFAULT_MAX_STAGING_BYTES = DEFAULT_MAX_PLAINTEXT_BYTES + MAX_PRIVATE_METADATA_BYTES + 64
      DEFAULT_MAX_ENVELOPE_BYTES =
        MAX_HEADER_BYTES +
        (2 + SECTION_ID_BYTES + MAX_RECIPIENT_CAPACITY * MAX_SLOT_SIZE) +
        DEFAULT_MAX_STAGING_BYTES +
        TAG_BYTES

      LIMIT_DEFAULTS = {
        max_staging_bytes: DEFAULT_MAX_STAGING_BYTES,
        max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
        max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES
      }.freeze

      HEADER_PREFIX_BYTES = MAGIC.bytesize + 1 + 4
      INNER_PREFIX_BYTES = 14

      Header = Struct.new(
        :raw, :content_suite_id, :lookup_mode, :flags, :padding_policy_id,
        :payload_id, :payload_nonce, :recipient_capacity, :slot_size,
        :padded_inner_length, :public_metadata,
        keyword_init: true
      )

      Section = Struct.new(
        :wrap_suite_id, :section_id, :raw, :slots_offset, :slots_length,
        keyword_init: true
      )

      VerifiedInner = Struct.new(:content, :metadata, :padding_bytes, keyword_init: true)

      SLOT_FIELDS = [
        [:hint, HINT_BYTES],
        [:kem_ciphertext, XWING_CIPHERTEXT_BYTES],
        [:wrap_nonce, NONCE_BYTES],
        [:wrapped_dek, DEK_BYTES],
        [:wrap_tag, TAG_BYTES]
      ].freeze

      class HeaderCodec
        class << self
          def build(payload_id:, payload_nonce:, recipient_capacity:, slot_size:,
                    padded_inner_length:, public_metadata:, padding_policy_id:)
            public_metadata = String(public_metadata).b
            validate_build_input!(
              payload_id, payload_nonce, public_metadata, padding_policy_id
            )

            body = [
              Binary.u16(CONTENT_SUITE_AEGIS256),
              Binary.u8(LOOKUP_HINT),
              Binary.u16(FLAGS),
              Binary.u8(padding_policy_id),
              payload_id,
              payload_nonce,
              Binary.u16(recipient_capacity),
              Binary.u16(slot_size),
              Binary.u64(padded_inner_length),
              Binary.u32(public_metadata.bytesize),
              public_metadata
            ].join.b

            header = MAGIC + Binary.u8(VERSION) + Binary.u32(HEADER_PREFIX_BYTES + body.bytesize) + body
            raise InvalidConfigurationError, "header is too large" if header.bytesize > MAX_HEADER_BYTES

            header
          end

          def parse(bytes)
            source = String(bytes).b
            prefix = Binary::Reader.new(source)
            expect!(prefix.bytes(MAGIC.bytesize), MAGIC, "invalid envelope magic")
            expect!(prefix.u8, VERSION, "unsupported format version")
            header_length = prefix.u32
            validate_header_length!(header_length, prefix.offset)

            Binary.ensure_available!(source, 0, header_length)
            raw = source.byteslice(0, header_length).b
            fields = Binary::Reader.new(raw, prefix.offset)

            content_suite = fields.u16
            expect_suite!(content_suite, CONTENT_SUITE_AEGIS256, "content")
            lookup_mode = fields.u8
            expect_suite!(lookup_mode, LOOKUP_HINT, "lookup mode")
            flags = fields.u16
            expect!(flags, FLAGS, "unknown header flags")
            padding_policy_id = Format.validate_padding_policy_id!(fields.u8, error: FormatError)
            payload_id = fields.bytes(PAYLOAD_ID_BYTES)
            payload_nonce = fields.bytes(NONCE_BYTES)
            capacity = Format.validate_capacity!(fields.u16, error: FormatError)
            slot_size = Format.validate_slot_size!(fields.u16, error: FormatError)
            padded_inner_length = fields.u64
            raise FormatError, "padded inner frame is too short" if padded_inner_length < INNER_PREFIX_BYTES

            public_length = fields.u32
            raise FormatError, "public metadata is too large" if public_length > MAX_PUBLIC_METADATA_BYTES
            public_metadata = fields.bytes(public_length)
            raise FormatError, "non-canonical header length" unless fields.finished?

            Header.new(
              raw: raw,
              content_suite_id: content_suite,
              lookup_mode: lookup_mode,
              flags: flags,
              padding_policy_id: padding_policy_id,
              payload_id: payload_id,
              payload_nonce: payload_nonce,
              recipient_capacity: capacity,
              slot_size: slot_size,
              padded_inner_length: padded_inner_length,
              public_metadata: public_metadata
            )
          end

          private

          def validate_build_input!(payload_id, payload_nonce, public_metadata, padding_policy_id)
            raise InvalidConfigurationError, "public metadata is too large" if public_metadata.bytesize > MAX_PUBLIC_METADATA_BYTES
            raise InvalidConfigurationError, "invalid payload_id" unless payload_id.bytesize == PAYLOAD_ID_BYTES
            raise InvalidConfigurationError, "invalid payload nonce" unless payload_nonce.bytesize == NONCE_BYTES

            Format.validate_padding_policy_id!(padding_policy_id, error: InvalidConfigurationError)
          end

          def validate_header_length!(length, minimum)
            return if length.between?(minimum, MAX_HEADER_BYTES)

            raise FormatError, "invalid header length"
          end

          def expect!(actual, expected, message)
            return if actual == expected

            suffix = message.start_with?("unsupported") ? " #{actual}" : ""
            raise FormatError, "#{message}#{suffix}"
          end

          def expect_suite!(actual, expected, label)
            return if actual == expected

            raise UnsupportedSuiteError, "unsupported #{label} #{actual}"
          end
        end
      end

      class SectionCodec
        class << self
          def parse(bytes, offset, header)
            raw, = Binary.read_bytes(bytes, offset, Format.section_length(header))
            reader = Binary::Reader.new(raw)
            wrap_suite = reader.u16
            unless wrap_suite == WRAP_SUITE_MLKEM768_X25519_AEGIS256
              raise UnsupportedSuiteError, "unsupported wrap suite #{wrap_suite}"
            end

            section_id = reader.bytes(SECTION_ID_BYTES)
            Section.new(
              wrap_suite_id: wrap_suite,
              section_id: section_id,
              raw: raw,
              slots_offset: reader.offset,
              slots_length: raw.bytesize - reader.offset
            )
          end
        end
      end

      class InnerCodec
        class << self
          def prefix(content_length, metadata_length)
            Binary.u8(INNER_VERSION) + Binary.u8(INNER_FLAGS) +
              Binary.u64(content_length) + Binary.u32(metadata_length)
          end

          def parse(bytes)
            source = String(bytes).b
            reader = Binary::Reader.new(source)
            raise FormatError, "unsupported inner version" unless reader.u8 == INNER_VERSION
            raise FormatError, "unknown inner flags" unless reader.u8 == INNER_FLAGS

            content_length = reader.u64
            metadata_length = reader.u32
            raise FormatError, "private metadata is too large" if metadata_length > MAX_PRIVATE_METADATA_BYTES

            metadata = reader.bytes(metadata_length)
            content = reader.bytes(content_length)
            VerifiedInner.new(
              content: content,
              metadata: metadata,
              padding_bytes: source.bytesize - reader.offset
            )
          end
        end
      end

      module_function

      def validate_slot_size!(slot_size, error: InvalidConfigurationError)
        size = Integer(slot_size)
        valid = size.between?(MIN_SLOT_SIZE, MAX_SLOT_SIZE) && (size % SLOT_GRANULARITY).zero?
        raise error, "slot_size must be #{MIN_SLOT_SIZE}..#{MAX_SLOT_SIZE} and divisible by #{SLOT_GRANULARITY}" unless valid
        raise error, "slot_size is too small for current wrap suite" if size < STANZA_BYTES

        size
      end

      def validate_capacity!(capacity, recipient_count = nil, error: InvalidConfigurationError)
        value = Integer(capacity)
        raise error, "recipient_capacity must be 1..#{MAX_RECIPIENT_CAPACITY}" unless value.between?(1, MAX_RECIPIENT_CAPACITY)
        raise RecipientCapacityExceeded, "#{recipient_count} recipients do not fit capacity #{value}" if recipient_count && recipient_count > value

        value
      end

      def validate_padding_policy_id!(policy_id, error: FormatError)
        value = Integer(policy_id)
        raise error, "unsupported padding policy id #{value}" unless PADDING_POLICY_IDS.include?(value)

        value
      end

      def build_header(**attributes)
        HeaderCodec.build(**attributes)
      end

      def parse_header(bytes)
        HeaderCodec.parse(bytes)
      end

      def section_length(header)
        section_length_for(header.recipient_capacity, header.slot_size)
      end

      def section_length_for(capacity, slot_size)
        2 + SECTION_ID_BYTES + Integer(capacity) * Integer(slot_size)
      end

      def parse_section(bytes, offset, header)
        SectionCodec.parse(bytes, offset, header)
      end

      def split_slot(slot, slot_size)
        reader = Binary::Reader.new(slot)
        fields = SLOT_FIELDS.each_with_object({}) do |(name, length), result|
          result[name] = reader.bytes(length)
        end
        fields[:padding] = reader.bytes(Integer(slot_size) - reader.offset)
        fields
      end

      def inner_prefix(content_length, private_metadata_length)
        InnerCodec.prefix(content_length, private_metadata_length)
      end

      def parse_verified_inner(bytes)
        inner = InnerCodec.parse(bytes)
        [inner.content, inner.metadata, inner.padding_bytes]
      end
    end
  end
end

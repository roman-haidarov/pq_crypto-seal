# frozen_string_literal: true

module PQCrypto
  module Seal
    module Format
      module Identifiers
        MAGIC = 'PQCSEAL1'.b.freeze
        VERSION = 1
        CONTENT_SUITE_AEGIS256 = 1
        WRAP_SUITE_MLKEM768_X25519_AEGIS256 = 1
        LOOKUP_HINT = 1
      end

      module Flags
        FLAGS = 0
        INNER_VERSION = 1
        INNER_FLAGS = 0
      end

      module PaddingIds
        PADDING_NONE = 0
        PADDING_PADME = 1
        PADDING_FIXED = 2
        PADDING_BUCKETS = 3
        PADDING_POLICY_IDS = [PADDING_NONE, PADDING_PADME, PADDING_FIXED, PADDING_BUCKETS].freeze
      end

      module FieldSizes
        PAYLOAD_ID_BYTES = 32
        NONCE_BYTES = 32
        TAG_BYTES = 32
        HINT_BYTES = 32
        SECTION_ID_BYTES = 32
      end

      module WrapSizes
        XWING_PUBLIC_KEY_BYTES = 1216
        XWING_CIPHERTEXT_BYTES = 1120
        XWING_SHARED_SECRET_BYTES = 32
        DEK_BYTES = 32
        STANZA_BYTES = FieldSizes::HINT_BYTES + XWING_CIPHERTEXT_BYTES + FieldSizes::NONCE_BYTES +
                       DEK_BYTES + FieldSizes::TAG_BYTES
      end

      module SlotGeometry
        DEFAULT_SLOT_SIZE = 2048
        MIN_SLOT_SIZE = 2048
        MAX_SLOT_SIZE = 8192
        SLOT_GRANULARITY = 256
        SLOT_FIELDS = [
          [:hint, FieldSizes::HINT_BYTES],
          [:kem_ciphertext, WrapSizes::XWING_CIPHERTEXT_BYTES],
          [:wrap_nonce, FieldSizes::NONCE_BYTES],
          [:wrapped_dek, WrapSizes::DEK_BYTES],
          [:wrap_tag, FieldSizes::TAG_BYTES]
        ].map(&:freeze).freeze
      end

      module Ceilings
        DEFAULT_RECIPIENT_CAPACITY = 4
        MAX_RECIPIENT_CAPACITY = 32
        MAX_PUBLIC_METADATA_BYTES = 1 * 1024 * 1024
        MAX_PRIVATE_METADATA_BYTES = 16 * 1024 * 1024
        MAX_HEADER_BYTES = 2 * 1024 * 1024
      end

      module Prefixes
        HEADER_PREFIX_BYTES = Identifiers::MAGIC.bytesize + 1 + 4
        SECTION_PREFIX_BYTES = 2 + FieldSizes::SECTION_ID_BYTES
        INNER_PREFIX_BYTES = 14
      end

      module LimitDefaults
        DEFAULT_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
        DEFAULT_MAX_STAGING_BYTES = DEFAULT_MAX_PLAINTEXT_BYTES + Ceilings::MAX_PRIVATE_METADATA_BYTES + 64
        DEFAULT_MAX_ENVELOPE_BYTES =
          Ceilings::MAX_HEADER_BYTES +
          Prefixes::SECTION_PREFIX_BYTES + (Ceilings::MAX_RECIPIENT_CAPACITY * SlotGeometry::MAX_SLOT_SIZE) +
          DEFAULT_MAX_STAGING_BYTES +
          FieldSizes::TAG_BYTES
        LIMIT_DEFAULTS = {
          max_staging_bytes: DEFAULT_MAX_STAGING_BYTES,
          max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
          max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES
        }.freeze
      end

      include Identifiers
      include Flags
      include PaddingIds
      include FieldSizes
      include WrapSizes
      include SlotGeometry
      include Ceilings
      include Prefixes
      include LimitDefaults

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

      VerifiedInner = Struct.new(:content, :metadata, :padding_bytes, keyword_init: true) do
        def wipe
          Secrets.wipe_each!(content, metadata)
        end
      end

      SuiteCheck = Struct.new(:expected, :label) do
        def call(actual)
          return actual if actual == expected

          raise UnsupportedSuiteError, "unsupported #{label} #{actual}"
        end
      end

      ValueCheck = Struct.new(:expected, :message) do
        def call(actual)
          return actual if actual == expected

          raise FormatError, message
        end
      end

      module_function

      def validate_slot_size!(slot_size, error: InvalidConfigurationError)
        size = Integer(slot_size)
        valid = size.between?(MIN_SLOT_SIZE, MAX_SLOT_SIZE) && (size % SLOT_GRANULARITY).zero?
        unless valid
          raise error, "slot_size must be #{MIN_SLOT_SIZE}..#{MAX_SLOT_SIZE} and divisible by " \
                       "#{SLOT_GRANULARITY}"
        end
        raise error, 'slot_size is too small for current wrap suite' if size < STANZA_BYTES

        size
      end

      def validate_capacity!(capacity, error: InvalidConfigurationError)
        value = Integer(capacity)
        return value if value.between?(1, MAX_RECIPIENT_CAPACITY)

        raise error, "recipient_capacity must be 1..#{MAX_RECIPIENT_CAPACITY}"
      end

      def validate_recipient_count!(capacity, recipient_count)
        return capacity if recipient_count <= capacity

        raise RecipientCapacityExceeded, "#{recipient_count} recipients do not fit capacity #{capacity}"
      end

      def validate_padding_policy_id!(policy_id, error: FormatError)
        value = Integer(policy_id)
        return value if PADDING_POLICY_IDS.include?(value)

        raise error, "unsupported padding policy id #{value}"
      end

      def validate_header_length!(length)
        return length if length.between?(HEADER_PREFIX_BYTES, MAX_HEADER_BYTES)

        raise FormatError, 'invalid header length'
      end

      def validate_inner_length!(length)
        return length if length >= INNER_PREFIX_BYTES

        raise FormatError, 'padded inner frame is too short'
      end

      def validate_private_metadata_length!(length)
        return length if length <= MAX_PRIVATE_METADATA_BYTES

        raise FormatError, 'private metadata is too large'
      end

      def section_length(header)
        section_length_for(header.recipient_capacity, header.slot_size)
      end

      def section_length_for(capacity, slot_size)
        SECTION_PREFIX_BYTES + (Integer(capacity) * Integer(slot_size))
      end
    end
  end
end

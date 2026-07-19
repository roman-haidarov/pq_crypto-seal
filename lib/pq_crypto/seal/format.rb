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

      PAYLOAD_ID_BYTES = 32
      NONCE_BYTES = 32
      TAG_BYTES = 32
      HINT_BYTES = 32
      SECTION_ID_BYTES = 32

      XWING_PUBLIC_KEY_BYTES = 1216
      XWING_CIPHERTEXT_BYTES = 1120
      XWING_SHARED_SECRET_BYTES = 32
      XWING_SECRET_KEY_BYTES = 32

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

      DEFAULT_MAX_PLAINTEXT_BYTES = 1 * 1024 * 1024 * 1024 # 1 GiB
      DEFAULT_MAX_STAGING_BYTES = DEFAULT_MAX_PLAINTEXT_BYTES + MAX_PRIVATE_METADATA_BYTES + 64
      DEFAULT_MAX_ENVELOPE_BYTES =
        MAX_HEADER_BYTES +
        (2 + SECTION_ID_BYTES + MAX_RECIPIENT_CAPACITY * MAX_SLOT_SIZE) +
        DEFAULT_MAX_STAGING_BYTES +
        TAG_BYTES

      Header = Struct.new(
        :raw, :content_suite_id, :lookup_mode, :flags, :padding_policy_id,
        :payload_id, :payload_nonce, :recipient_capacity, :slot_size,
        :padded_inner_length, :public_metadata,
        keyword_init: true
      )

      Section = Struct.new(:wrap_suite_id, :section_id, :raw, :slots_offset, :slots_length, keyword_init: true)

      module_function

      def validate_slot_size!(slot_size)
        n = Integer(slot_size)
        unless n.between?(MIN_SLOT_SIZE, MAX_SLOT_SIZE) && (n % SLOT_GRANULARITY).zero?
          raise InvalidConfigurationError,
                "slot_size must be #{MIN_SLOT_SIZE}..#{MAX_SLOT_SIZE} and divisible by #{SLOT_GRANULARITY}"
        end
        raise InvalidConfigurationError, "slot_size is too small for current wrap suite" if n < STANZA_BYTES
        n
      end

      def validate_capacity!(capacity, recipient_count = nil)
        n = Integer(capacity)
        unless n.between?(1, MAX_RECIPIENT_CAPACITY)
          raise InvalidConfigurationError, "recipient_capacity must be 1..#{MAX_RECIPIENT_CAPACITY}"
        end
        if recipient_count && recipient_count > n
          raise RecipientCapacityExceeded, "#{recipient_count} recipients do not fit capacity #{n}"
        end
        n
      end

      def validate_slot_size_from_wire!(slot_size)
        n = Integer(slot_size)
        unless n.between?(MIN_SLOT_SIZE, MAX_SLOT_SIZE) && (n % SLOT_GRANULARITY).zero?
          raise FormatError,
                "slot_size must be #{MIN_SLOT_SIZE}..#{MAX_SLOT_SIZE} and divisible by #{SLOT_GRANULARITY}"
        end
        raise FormatError, "slot_size is too small for current wrap suite" if n < STANZA_BYTES
        n
      end

      def validate_capacity_from_wire!(capacity)
        n = Integer(capacity)
        unless n.between?(1, MAX_RECIPIENT_CAPACITY)
          raise FormatError, "recipient_capacity must be 1..#{MAX_RECIPIENT_CAPACITY}"
        end
        n
      end

      def validate_padding_policy_id!(policy_id)
        n = Integer(policy_id)
        unless [PADDING_NONE, PADDING_PADME, PADDING_FIXED, PADDING_BUCKETS].include?(n)
          raise FormatError, "unsupported padding policy id #{n}"
        end
        n
      end

      def padding_policy_id_for(policy)
        case policy
        when nil, :none then PADDING_NONE
        when :padme then PADDING_PADME
        when :preserve
          raise InvalidConfigurationError, "padding: :preserve is only valid for rotate_dek"
        when Hash
          if policy.key?(:to)
            PADDING_FIXED
          elsif policy.key?(:buckets)
            PADDING_BUCKETS
          else
            raise InvalidConfigurationError, "padding hash must contain :to or :buckets"
          end
        else
          raise InvalidConfigurationError, "unsupported padding policy: #{policy.inspect}"
        end
      end

      def build_header(payload_id:, payload_nonce:, recipient_capacity:, slot_size:,
                       padded_inner_length:, public_metadata:, padding_policy_id:)
        public_metadata = String(public_metadata).b
        raise InvalidConfigurationError, "public metadata is too large" if public_metadata.bytesize > MAX_PUBLIC_METADATA_BYTES
        raise InvalidConfigurationError, "invalid payload_id" unless payload_id.bytesize == PAYLOAD_ID_BYTES
        raise InvalidConfigurationError, "invalid payload nonce" unless payload_nonce.bytesize == NONCE_BYTES
        validate_padding_policy_id!(padding_policy_id)

        body = +"".b
        body << Binary.u16(CONTENT_SUITE_AEGIS256)
        body << Binary.u8(LOOKUP_HINT)
        body << Binary.u16(FLAGS)
        body << Binary.u8(Integer(padding_policy_id))
        body << payload_id
        body << payload_nonce
        body << Binary.u16(recipient_capacity)
        body << Binary.u16(slot_size)
        body << Binary.u64(padded_inner_length)
        body << Binary.u32(public_metadata.bytesize)
        body << public_metadata
        header = MAGIC + Binary.u8(VERSION) + Binary.u32(MAGIC.bytesize + 1 + 4 + body.bytesize) + body
        raise InvalidConfigurationError, "header is too large" if header.bytesize > MAX_HEADER_BYTES
        header
      end

      def parse_header(bytes)
        bytes = String(bytes).b
        offset = 0
        magic, offset = Binary.read_bytes(bytes, offset, MAGIC.bytesize)
        raise FormatError, "invalid envelope magic" unless magic == MAGIC
        version, offset = Binary.read_u8(bytes, offset)
        raise FormatError, "unsupported format version #{version}" unless version == VERSION
        header_length, offset = Binary.read_u32(bytes, offset)
        raise FormatError, "invalid header length" if header_length < offset || header_length > MAX_HEADER_BYTES
        Binary.ensure_available!(bytes, 0, header_length)
        raw = bytes.byteslice(0, header_length).b

        content_suite, offset = Binary.read_u16(raw, offset)
        raise UnsupportedSuiteError, "unsupported content suite #{content_suite}" unless content_suite == CONTENT_SUITE_AEGIS256
        lookup_mode, offset = Binary.read_u8(raw, offset)
        raise UnsupportedSuiteError, "unsupported lookup mode #{lookup_mode}" unless lookup_mode == LOOKUP_HINT
        flags, offset = Binary.read_u16(raw, offset)
        raise FormatError, "unknown header flags" unless flags == FLAGS
        padding_policy_id, offset = Binary.read_u8(raw, offset)
        validate_padding_policy_id!(padding_policy_id)
        payload_id, offset = Binary.read_bytes(raw, offset, PAYLOAD_ID_BYTES)
        payload_nonce, offset = Binary.read_bytes(raw, offset, NONCE_BYTES)
        capacity, offset = Binary.read_u16(raw, offset)
        validate_capacity_from_wire!(capacity)
        slot_size, offset = Binary.read_u16(raw, offset)
        validate_slot_size_from_wire!(slot_size)
        padded_inner_length, offset = Binary.read_u64(raw, offset)
        raise FormatError, "padded inner frame is too short" if padded_inner_length < 14
        public_length, offset = Binary.read_u32(raw, offset)
        raise FormatError, "public metadata is too large" if public_length > MAX_PUBLIC_METADATA_BYTES
        public_metadata, offset = Binary.read_bytes(raw, offset, public_length)
        raise FormatError, "non-canonical header length" unless offset == raw.bytesize

        Header.new(
          raw: raw, content_suite_id: content_suite, lookup_mode: lookup_mode,
          flags: flags, padding_policy_id: padding_policy_id,
          payload_id: payload_id, payload_nonce: payload_nonce,
          recipient_capacity: capacity, slot_size: slot_size,
          padded_inner_length: padded_inner_length, public_metadata: public_metadata
        )
      end

      def section_length(header)
        section_length_for(header.recipient_capacity, header.slot_size)
      end

      def section_length_for(capacity, slot_size)
        2 + SECTION_ID_BYTES + Integer(capacity) * Integer(slot_size)
      end

      def parse_section(bytes, offset, header)
        length = section_length(header)
        raw, = Binary.read_bytes(bytes, offset, length)
        wrap_suite, slot_offset = Binary.read_u16(raw, 0)
        section_id, slot_offset = Binary.read_bytes(raw, slot_offset, SECTION_ID_BYTES)
        unless wrap_suite == WRAP_SUITE_MLKEM768_X25519_AEGIS256
          raise UnsupportedSuiteError, "unsupported wrap suite #{wrap_suite}"
        end
        Section.new(wrap_suite_id: wrap_suite, section_id: section_id, raw: raw, slots_offset: slot_offset,
                    slots_length: raw.bytesize - slot_offset)
      end

      def inner_prefix(content_length, private_metadata_length)
        Binary.u8(INNER_VERSION) + Binary.u8(INNER_FLAGS) +
          Binary.u64(content_length) + Binary.u32(private_metadata_length)
      end

      def parse_verified_inner(bytes)
        bytes = String(bytes).b
        offset = 0
        version, offset = Binary.read_u8(bytes, offset)
        raise FormatError, "unsupported inner version" unless version == INNER_VERSION
        flags, offset = Binary.read_u8(bytes, offset)
        raise FormatError, "unknown inner flags" unless flags == INNER_FLAGS
        content_length, offset = Binary.read_u64(bytes, offset)
        metadata_length, offset = Binary.read_u32(bytes, offset)
        raise FormatError, "private metadata is too large" if metadata_length > MAX_PRIVATE_METADATA_BYTES
        metadata, offset = Binary.read_bytes(bytes, offset, metadata_length)
        content, offset = Binary.read_bytes(bytes, offset, content_length)
        [content, metadata, bytes.bytesize - offset]
      end

      def check_resource_limits!(padded_inner_length:, envelope_bytes: nil,
                                 max_staging_bytes: DEFAULT_MAX_STAGING_BYTES,
                                 max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
                                 max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES)
        if padded_inner_length > Integer(max_staging_bytes)
          raise ResourceLimitError,
                "padded_inner_length #{padded_inner_length} exceeds max_staging_bytes #{max_staging_bytes}"
        end

        if envelope_bytes && envelope_bytes > Integer(max_envelope_bytes)
          raise ResourceLimitError,
                "envelope #{envelope_bytes} exceeds max_envelope_bytes #{max_envelope_bytes}"
        end
        true
      end
    end
  end
end

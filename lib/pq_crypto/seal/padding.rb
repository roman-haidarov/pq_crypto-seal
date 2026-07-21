# frozen_string_literal: true

module PQCrypto
  module Seal
    module Padding
      Verification = Struct.new(
        :header, :envelope_bytes, :content_bytes, :metadata_bytes,
        keyword_init: true
      ) do
        def raw_inner_bytes
          Format::INNER_PREFIX_BYTES + metadata_bytes + content_bytes
        end

        def unpadded_envelope_bytes
          envelope_bytes - header.padded_inner_length + raw_inner_bytes
        end
      end

      class Policy
        attr_reader :id

        def initialize(id)
          @id = id
          freeze
        end

        def target(_base_length)
          raise NotImplementedError
        end

        def verify!(context)
          verify_header!(context.header)
          verify_target!(context)
          true
        end

        private

        def verify_header!(header)
          return if header.padding_policy_id == id

          raise FormatError,
                "header padding_policy_id=#{header.padding_policy_id} does not match required policy #{id}"
        end

        def verify_target!(context)
          expected = target(context.unpadded_envelope_bytes)
          return if context.envelope_bytes == expected

          raise FormatError,
                "envelope size #{context.envelope_bytes} does not satisfy required padding target #{expected}"
        end
      end

      class NonePolicy < Policy
        def initialize
          super(Format::PADDING_NONE)
        end

        def target(base_length)
          Integer(base_length)
        end
      end

      class PadmePolicy < Policy
        def initialize
          super(Format::PADDING_PADME)
        end

        def target(base_length)
          Padding.padme_target(base_length)
        end
      end

      class FixedPolicy < Policy
        attr_reader :size

        def initialize(size)
          @size = Integer(size)
          raise InvalidConfigurationError, "padding target must be non-negative" if @size.negative?

          super(Format::PADDING_FIXED)
        end

        def target(base_length)
          raise InvalidConfigurationError, "padding target is smaller than envelope" if size < Integer(base_length)

          size
        end
      end

      class BucketsPolicy < Policy
        attr_reader :buckets

        def initialize(values)
          @buckets = Array(values).map { |value| Integer(value) }.uniq.sort.freeze
          raise InvalidConfigurationError, "padding buckets must not be empty" if @buckets.empty?
          raise InvalidConfigurationError, "padding buckets must be non-negative" if @buckets.first.negative?

          super(Format::PADDING_BUCKETS)
        end

        def target(base_length)
          bucket = buckets.bsearch { |value| value >= Integer(base_length) }
          raise InvalidConfigurationError, "no padding bucket can hold envelope" unless bucket

          bucket
        end
      end

      class NoRequirement
        def verify!(_context)
          true
        end
      end

      class PolicyIdRequirement
        def initialize(policy_id)
          @policy_id = Integer(policy_id)
          freeze
        end

        def verify!(context)
          actual = context.header.padding_policy_id
          return true if actual == @policy_id

          raise FormatError,
                "header padding_policy_id=#{actual} does not match required policy #{@policy_id}"
        end
      end

      NONE = NonePolicy.new
      PADME = PadmePolicy.new
      NO_REQUIREMENT = NoRequirement.new.freeze

      SIMPLE_POLICIES = {
        nil => NONE,
        false => NO_REQUIREMENT,
        none: NONE,
        padme: PADME
      }.freeze

      HEADER_POLICIES = {
        Format::PADDING_NONE => NONE,
        Format::PADDING_PADME => PADME,
        Format::PADDING_FIXED => PolicyIdRequirement.new(Format::PADDING_FIXED),
        Format::PADDING_BUCKETS => PolicyIdRequirement.new(Format::PADDING_BUCKETS)
      }.freeze

      module_function

      def padme_target(length)
        value = Integer(length)
        raise ArgumentError, "length must be non-negative" if value.negative?
        return value if value <= 1

        exponent = value.bit_length - 1
        low_bits = exponent - exponent.bit_length
        return value unless low_bits.positive?

        mask = (1 << low_bits) - 1
        (value + mask) & ~mask
      end

      def for_encryption(value)
        return SIMPLE_POLICIES.fetch(value) if SIMPLE_POLICIES.key?(value) && value != false
        return policy_from_hash(value) if value.is_a?(Hash)
        raise InvalidConfigurationError, "padding: :preserve is only valid for rotate_dek" if value == :preserve
        raise InvalidConfigurationError, "unsupported padding policy: #{value.inspect}"
      end

      def requirement(value, header_policy_id:)
        return NO_REQUIREMENT if value.nil? || value == false
        return policy_from_header(header_policy_id) if value == :from_header

        for_encryption(value)
      end

      def verify!(required, header:, envelope_bytes:, content_bytes:, metadata_bytes:)
        requirement(required, header_policy_id: header.padding_policy_id).verify!(
          Verification.new(
            header: header,
            envelope_bytes: envelope_bytes,
            content_bytes: content_bytes,
            metadata_bytes: metadata_bytes
          )
        )
      end

      def target(base_length, policy)
        for_encryption(policy).target(base_length)
      end

      def policy_id(policy)
        for_encryption(policy).id
      end

      def policy_from_hash(value)
        constructors = {
          to: -> { FixedPolicy.new(value.fetch(:to)) },
          buckets: -> { BucketsPolicy.new(value.fetch(:buckets)) }
        }
        key = constructors.keys.find { |candidate| value.key?(candidate) }
        raise InvalidConfigurationError, "padding hash must contain :to or :buckets" unless key

        constructors.fetch(key).call
      end

      def policy_from_header(policy_id)
        HEADER_POLICIES.fetch(policy_id) do
          raise FormatError, "unknown padding_policy_id in header: #{policy_id}"
        end
      end

      private_class_method :policy_from_hash, :policy_from_header
    end
  end
end

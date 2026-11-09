# frozen_string_literal: true

module PQCrypto
  module Seal
    module Padding
      Verification = Struct.new(:header, :envelope_bytes, :content_bytes, :metadata_bytes, keyword_init: true) do
        def policy_id
          header.padding_policy_id
        end

        def unpadded_envelope_bytes
          envelope_bytes - header.padded_inner_length + Format::INNER_PREFIX_BYTES + metadata_bytes + content_bytes
        end
      end

      class Policy
        attr_reader :id

        def initialize(id, &rule)
          @id = id
          @rule = rule
          freeze
        end

        def target(base_length)
          @rule.call(Integer(base_length))
        end

        def verify(context)
          Padding.check_policy_id(context, id)
          expected = target(context.unpadded_envelope_bytes)
          actual = context.envelope_bytes
          return self if actual == expected

          raise FormatError, "envelope size #{actual} does not satisfy required padding target #{expected}"
        end
      end

      PolicyIdRequirement = Struct.new(:id) do
        def verify(context)
          Padding.check_policy_id(context, id)
          self
        end
      end

      class NoRequirement
        def verify(_context)
          self
        end
      end

      NONE = Policy.new(Format::PADDING_NONE) { |length| length }
      PADME = Policy.new(Format::PADDING_PADME) { |length| Padding.padme_target(length) }
      NO_REQUIREMENT = NoRequirement.new.freeze
      ENCRYPTION_POLICIES = { nil => NONE, none: NONE, padme: PADME }.freeze
      HEADER_POLICIES = {
        Format::PADDING_NONE => NONE,
        Format::PADDING_PADME => PADME,
        Format::PADDING_FIXED => PolicyIdRequirement.new(Format::PADDING_FIXED).freeze,
        Format::PADDING_BUCKETS => PolicyIdRequirement.new(Format::PADDING_BUCKETS).freeze
      }.freeze

      module_function

      def padme_target(length)
        value = Integer(length)
        raise ArgumentError, 'length must be non-negative' if value.negative?

        mask = (1 << padme_low_bits(value)) - 1
        (value + mask) & ~mask
      end

      def padme_low_bits(value)
        return 0 if value <= 1

        exponent = value.bit_length - 1
        [exponent - exponent.bit_length, 0].max
      end

      def fixed(size)
        target = Integer(size)
        raise InvalidConfigurationError, 'padding target must be non-negative' if target.negative?

        Policy.new(Format::PADDING_FIXED) { |length| Padding.fixed_target(target, length) }
      end

      def fixed_target(target, length)
        return target if target >= length

        raise InvalidConfigurationError, 'padding target is smaller than envelope'
      end

      def buckets(values)
        sizes = bucket_sizes(values)
        Policy.new(Format::PADDING_BUCKETS) { |length| Padding.bucket_target(sizes, length) }
      end

      def bucket_sizes(values)
        sizes = Array(values).map { |value| Integer(value) }.uniq.sort.freeze
        raise InvalidConfigurationError, 'padding buckets must not be empty' if sizes.empty?
        raise InvalidConfigurationError, 'padding buckets must be non-negative' if sizes.first.negative?

        sizes
      end

      def bucket_target(sizes, length)
        sizes.bsearch { |size| size >= length } ||
          raise(InvalidConfigurationError, 'no padding bucket can hold envelope')
      end

      def for_encryption(value)
        ENCRYPTION_POLICIES.fetch(value) { policy_from_option(value) }
      end

      def requirement(value, header_policy_id)
        return NO_REQUIREMENT unless value
        return policy_from_header(header_policy_id) if value == :from_header

        for_encryption(value)
      end

      def verify(required, context)
        requirement(required, context.policy_id).verify(context)
      end

      def check_policy_id(context, expected)
        actual = context.policy_id
        return if actual == expected

        raise FormatError, "header padding_policy_id=#{actual} does not match required policy #{expected}"
      end

      def policy_from_option(value)
        return policy_from_hash(value) if value.is_a?(Hash)
        raise InvalidConfigurationError, 'padding: :preserve is only valid for rotate_dek' if value == :preserve

        raise InvalidConfigurationError, "unsupported padding policy: #{value.inspect}"
      end

      def policy_from_hash(value)
        return fixed(value.fetch(:to)) if value.key?(:to)
        return buckets(value.fetch(:buckets)) if value.key?(:buckets)

        raise InvalidConfigurationError, 'padding hash must contain :to or :buckets'
      end

      def policy_from_header(policy_id)
        HEADER_POLICIES.fetch(policy_id) do
          raise FormatError, "unknown padding_policy_id in header: #{policy_id}"
        end
      end

      private_class_method :padme_low_bits, :bucket_sizes, :policy_from_option, :policy_from_hash, :policy_from_header
    end
  end
end

# frozen_string_literal: true

module PQCrypto
  module Seal
    module Padding
      module_function

      def padme_target(length)
        n = Integer(length)
        raise ArgumentError, "length must be non-negative" if n.negative?
        return n if n <= 1

        exponent = n.bit_length - 1
        significant = exponent.bit_length
        low_bits = exponent - significant
        return n if low_bits <= 0

        mask = (1 << low_bits) - 1
        (n + mask) & ~mask
      end

      def target(base_length, policy)
        case policy
        when nil, :none then base_length
        when :padme then padme_target(base_length)
        when Hash then fixed_or_buckets(base_length, policy)
        else
          raise InvalidConfigurationError, "unsupported padding policy: #{policy.inspect}"
        end
      end

      def fixed_or_buckets(base_length, policy)
        if policy.key?(:to)
          target = Integer(policy.fetch(:to))
          raise InvalidConfigurationError, "padding target is smaller than envelope" if target < base_length
          target
        elsif policy.key?(:buckets)
          bucket = Array(policy.fetch(:buckets)).map { |n| Integer(n) }.sort.find { |n| n >= base_length }
          raise InvalidConfigurationError, "no padding bucket can hold envelope" unless bucket
          bucket
        else
          raise InvalidConfigurationError, "padding hash must contain :to or :buckets"
        end
      end
    end
  end
end

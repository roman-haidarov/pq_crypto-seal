# frozen_string_literal: true

module PQCrypto
  module Seal
    class ResourceLimits
      NAMES = %i[max_staging_bytes max_plaintext_bytes max_envelope_bytes].freeze

      attr_reader(*NAMES)

      def self.resolve(overrides = nil)
        return overrides if overrides.is_a?(self)

        new(Format::LIMIT_DEFAULTS.merge(overrides || {}))
      end

      def initialize(values)
        unknown = values.keys.map(&:to_sym) - NAMES
        raise ArgumentError, "unknown resource limits: #{unknown.join(', ')}" unless unknown.empty?

        NAMES.each do |name|
          value = Integer(values.fetch(name))
          raise ArgumentError, "#{name} must be positive" unless value.positive?

          instance_variable_set("@#{name}", value)
        end
        freeze
      end

      def check_envelope!(bytes)
        enforce!(:envelope, bytes, max_envelope_bytes)
      end

      def check_staging!(bytes)
        enforce!(:padded_inner_length, bytes, max_staging_bytes)
      end

      def check_plaintext!(bytes)
        enforce!(:plaintext, bytes, max_plaintext_bytes)
      end

      def check_declared!(header, envelope_bytes: nil)
        check_staging!(header.padded_inner_length)
        check_envelope!(envelope_bytes) if envelope_bytes
        self
      end

      private

      def enforce!(label, actual, maximum)
        return if Integer(actual) <= maximum

        raise ResourceLimitError, "#{label} #{actual} exceeds limit #{maximum}"
      end
    end
  end
end

# frozen_string_literal: true

module PQCrypto
  module Seal
    class ResourceLimits
      NAMES = %i[max_staging_bytes max_plaintext_bytes max_envelope_bytes].freeze

      attr_reader(*NAMES)

      class << self
        def resolve(overrides = nil)
          return overrides if overrides.is_a?(self)

          new(Format::LIMIT_DEFAULTS.merge(normalized(overrides.to_h)))
        end

        def checked(values)
          unknown = values.keys - NAMES
          raise ArgumentError, "unknown resource limits: #{unknown.join(', ')}" unless unknown.empty?

          NAMES.to_h { |name| [name, positive(values, name)] }
        end

        def positive(values, name)
          value = Integer(values.fetch(name))
          raise ArgumentError, "#{name} must be positive" unless value.positive?

          value
        end

        private

        def normalized(overrides)
          overrides.each_with_object({}) do |(key, value), names|
            name = key.is_a?(String) ? key.to_sym : key
            raise ArgumentError, "resource limit #{name} is given more than once" if names.key?(name)

            names[name] = value
          end
        end
      end

      def initialize(values)
        @max_staging_bytes, @max_plaintext_bytes, @max_envelope_bytes = ResourceLimits.checked(values).values_at(*NAMES)
        freeze
      end

      def check_envelope(bytes)
        enforce(:max_envelope_bytes, :envelope, bytes)
      end

      def check_staging(bytes)
        enforce(:max_staging_bytes, :padded_inner_length, bytes)
      end

      def check_plaintext(bytes)
        enforce(:max_plaintext_bytes, :plaintext, bytes)
      end

      def check_declared(header, envelope_bytes)
        check_staging(header.padded_inner_length)
        check_envelope(envelope_bytes)
        self
      end

      private

      def enforce(limit_name, label, actual)
        maximum = public_send(limit_name)
        return actual if Integer(actual) <= maximum

        raise ResourceLimitError, "#{label} #{actual} exceeds limit #{maximum}"
      end
    end
  end
end

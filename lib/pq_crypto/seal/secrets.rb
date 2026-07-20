# frozen_string_literal: true

module PQCrypto
  module Seal
    module Secrets
      module_function

      def wipe!(value)
        return unless value.is_a?(String) && !value.frozen?

        value.replace("\0".b * value.bytesize)
      rescue StandardError
        nil
      end

      def wipe_each!(*values)
        values.flatten.each { |value| wipe!(value) }
      end
    end
  end
end

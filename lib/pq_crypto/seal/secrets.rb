# frozen_string_literal: true

module PQCrypto
  module Seal
    module Secrets
      module_function

      def wipe!(value)
        Native.wipe(value)
      end

      def wipe_each!(*values)
        values.flatten.each { |value| wipe!(value) }
      end
    end
  end
end

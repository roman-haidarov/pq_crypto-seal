# frozen_string_literal: true

module PQCrypto
  module Seal
    class OptionSchema
      def initialize(required: [], defaults: {})
        @required = required.freeze
        @defaults = defaults.freeze
        @allowed = (@required + @defaults.keys).freeze
      end

      def resolve(options)
        keys = options.keys
        KeywordErrors.check('missing', @required - keys)
        KeywordErrors.check('unknown', keys - @allowed)
        @defaults.merge(options)
      end
    end

    module KeywordErrors
      module_function

      def check(kind, keys)
        return if keys.empty?

        noun = keys.one? ? 'keyword' : 'keywords'
        raise ArgumentError, "#{kind} #{noun}: #{keys.map(&:inspect).join(', ')}"
      end
    end
  end
end

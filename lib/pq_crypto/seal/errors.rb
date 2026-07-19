# frozen_string_literal: true

module PQCrypto
  module Seal
    class Error < StandardError; end
    class FormatError < Error; end
    class AuthenticationError < Error; end
    class UnsupportedSuiteError < FormatError; end
    class RecipientNotFoundError < AuthenticationError; end
    class AmbiguousRecipientStanzas < AuthenticationError; end
    class InvalidConfigurationError < Error; end
    class RecipientCapacityExceeded < InvalidConfigurationError; end
    class ResourceLimitError < Error; end
  end
end

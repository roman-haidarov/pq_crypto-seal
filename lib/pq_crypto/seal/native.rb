# frozen_string_literal: true

require "pq_crypto/seal/pq_crypto_seal"

module PQCrypto
  module Seal
    module Native
      KEY_BYTES = 32
      NONCE_BYTES = 32
      TAG_BYTES = 32
    end
  end
end

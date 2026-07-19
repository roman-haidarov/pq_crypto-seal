# frozen_string_literal: true

require "pq_crypto"
require "pq_crypto/seal/version"
require "pq_crypto/seal/errors"
require "pq_crypto/seal/native"
require "pq_crypto/seal/binary"
require "pq_crypto/seal/padding"
require "pq_crypto/seal/format"
require "pq_crypto/seal/core"
require "pq_crypto/seal/io"

module PQCrypto
  module Seal
    IO_DELEGATES = %i[
      encrypt_io decrypt_io encrypt_frame_io decrypt_frame_io
      encrypt_file decrypt_file rebuild_recipients_file
      add_recipient_file drop_recipient_stanza_file rotate_dek_file
      inspect_file
    ].freeze

    class << self
      IO_DELEGATES.each do |name|
        define_method(name) do |*args, **kwargs|
          IOAPI.public_send(name, *args, **kwargs)
        end
      end
    end

    private_constant :Native
  end
end

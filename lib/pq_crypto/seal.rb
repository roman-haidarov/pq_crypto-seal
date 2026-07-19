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
    class << self
      def encrypt_io(*args, **kwargs)
        IOAPI.encrypt_io(*args, **kwargs)
      end

      def decrypt_io(*args, **kwargs)
        IOAPI.decrypt_io(*args, **kwargs)
      end

      def encrypt_frame_io(*args, **kwargs)
        IOAPI.encrypt_frame_io(*args, **kwargs)
      end

      def decrypt_frame_io(*args, **kwargs)
        IOAPI.decrypt_frame_io(*args, **kwargs)
      end

      def encrypt_file(*args, **kwargs)
        IOAPI.encrypt_file(*args, **kwargs)
      end

      def decrypt_file(*args, **kwargs)
        IOAPI.decrypt_file(*args, **kwargs)
      end

      def rebuild_recipients_file(*args, **kwargs)
        IOAPI.rebuild_recipients_file(*args, **kwargs)
      end

      def add_recipient_file(*args, **kwargs)
        IOAPI.add_recipient_file(*args, **kwargs)
      end

      def drop_recipient_stanza_file(*args, **kwargs)
        IOAPI.drop_recipient_stanza_file(*args, **kwargs)
      end

      def rotate_dek_file(*args, **kwargs)
        IOAPI.rotate_dek_file(*args, **kwargs)
      end

      def inspect_file(*args, **kwargs)
        IOAPI.inspect_file(*args, **kwargs)
      end
    end

    private_constant :Native
  end
end

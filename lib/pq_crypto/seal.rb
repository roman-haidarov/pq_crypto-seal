# frozen_string_literal: true

require 'pq_crypto'
require 'pq_crypto/seal/version'
require 'pq_crypto/seal/errors'
require 'pq_crypto/seal/native'
require 'pq_crypto/seal/secrets'
require 'pq_crypto/seal/binary'
require 'pq_crypto/seal/options'
require 'pq_crypto/seal/format'
require 'pq_crypto/seal/format_codecs'
require 'pq_crypto/seal/models'
require 'pq_crypto/seal/resource_limits'
require 'pq_crypto/seal/padding'
require 'pq_crypto/seal/recipients'
require 'pq_crypto/seal/envelope'
require 'pq_crypto/seal/core'
require 'pq_crypto/seal/io_helpers'
require 'pq_crypto/seal/streaming'
require 'pq_crypto/seal/files'
require 'pq_crypto/seal/io'

module PQCrypto
  module Seal
    IO_DELEGATES = %i[
      encrypt_io decrypt_io encrypt_frame_io decrypt_frame_io
      encrypt_file decrypt_file rebuild_recipients_file
      add_recipient_file rotate_dek_file inspect_file
    ].freeze

    class << self
      IO_DELEGATES.each do |name|
        define_method(name) { |*args, **kwargs| IOAPI.public_send(name, *args, **kwargs) }
      end
    end

    private_constant :Native, :Secrets, :OptionSchema, :KeywordErrors,
                     :ResourceLimits, :KeyMaterial, :WrapSuite, :SectionSpec, :Stanza,
                     :SealedStanza, :StanzaSealer, :RecipientSectionBuilder, :SlotTable,
                     :RecipientSectionOpener, :EnvelopeParts, :Envelope, :PayloadIdentity,
                     :InnerFrame, :EncryptionSettings, :Plan, :EncryptionPlan,
                     :PrivateMetadata, :OneShotEncryptor, :OneShotOpener, :RecipientRebuilder,
                     :DekRotator, :RotationOptions, :IOHelpers, :CompleteWriter, :ExactReader,
                     :AtomicDestination, :StreamEnvelope, :AuthenticatedPass, :SizedSource,
                     :EncryptedWriter, :StreamingEncryptor, :StagedInner, :VerifiedStream,
                     :PlaintextMaterializer, :AuthenticatedStaging, :StreamingDecryptor,
                     :FilePaths, :FileRecipientRebuilder, :FileDekRotator, :FileOperation,
                     :FileInspection
  end
end

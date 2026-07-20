# frozen_string_literal: true

module PQCrypto
  module Seal
    WRAP_KEM_ALGORITHM = :ml_kem_768_x25519_xwing

    module KeyMaterial
      module_function

      def public_keys(value, allow_duplicates: false)
        keys = value.is_a?(Array) ? value : [value]
        raise InvalidConfigurationError, "at least one recipient is required" if keys.empty?

        keys.each { |key| validate_public_key!(key) }
        reject_duplicates!(keys) unless allow_duplicates
        keys
      end

      def credentials(value)
        secret_key, public_key = unpack_credentials(value)
        validate_secret_key!(secret_key)
        validate_public_key!(public_key, "credential public key is invalid")
        [secret_key, public_key]
      end

      def build_credentials(secret_key:, public_key:)
        validate_secret_key!(secret_key)
        validate_public_key!(public_key, "credential public key is invalid")
        Credentials.new(secret_key: secret_key, public_key: public_key).freeze
      end

      def validate_public_key!(key, message = nil)
        valid = key.is_a?(PQCrypto::HybridKEM::PublicKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, message || recipient_error unless valid

        assert_size!("X-Wing public key", key.to_bytes.bytesize, Format::XWING_PUBLIC_KEY_BYTES)
        key
      end

      def validate_secret_key!(key)
        valid = key.is_a?(PQCrypto::HybridKEM::SecretKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, "credential secret key is invalid" unless valid

        key
      end

      def assert_encapsulation!(encapsulation)
        assert_size!("X-Wing ciphertext", encapsulation.ciphertext.bytesize, Format::XWING_CIPHERTEXT_BYTES)
        assert_size!("X-Wing shared secret", encapsulation.shared_secret.bytesize, Format::XWING_SHARED_SECRET_BYTES)
        encapsulation
      end

      def assert_shared_secret!(secret, error: FormatError)
        assert_size!("X-Wing shared secret", secret.bytesize, Format::XWING_SHARED_SECRET_BYTES, error: error)
        secret
      end

      def assert_size!(label, actual, expected, error: InvalidConfigurationError)
        return if actual == expected

        raise error, "#{label} must be #{expected} bytes, got #{actual}"
      end

      def unpack_credentials(value)
        return [value.secret_key, value.public_key] if value.is_a?(PQCrypto::HybridKEM::Keypair)
        return [value.secret_key, value.public_key] if value.is_a?(Credentials)
        return value if value.is_a?(Array) && value.length == 2

        raise InvalidConfigurationError, credential_error
      end

      def reject_duplicates!(keys)
        fingerprints = keys.map { |key| Native.sha256(key.to_bytes) }
        return if fingerprints.uniq.length == fingerprints.length

        raise InvalidConfigurationError, "recipient list contains duplicate public keys"
      end

      def recipient_error
        "recipient must be an X-Wing public key (#{WRAP_KEM_ALGORITHM})"
      end

      def credential_error
        "with: must be a HybridKEM::Keypair, Seal.credentials(...), or [secret_key, public_key]"
      end

      private_class_method(*%i[unpack_credentials credential_error reject_duplicates! recipient_error])
    end

    module WrapSuiteV1
      HINT_DOMAIN = "PQC-SEAL-V1-RECIPIENT-HINT\0".b
      KEY_DOMAIN = "PQC-SEAL-V1-WRAP-KEY\0".b
      AD_DOMAIN = "PQC-SEAL-V1-WRAP-AD\0".b
      ID = Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256

      module_function

      def recipient_hint(public_key, payload_id, section_id, suite_id = ID)
        Native.sha256(
          HINT_DOMAIN + payload_id + section_id + Binary.u16(suite_id) + public_key.to_bytes
        )
      end

      def derive_kek(shared_secret, payload_id, section_id, suite_id, index)
        info = KEY_DOMAIN + payload_id + section_id + Binary.u16(suite_id) + Binary.u16(index)
        Native.hkdf_sha256(shared_secret, info, Format::DEK_BYTES)
      end

      def associated_data(header_hash, section_id, index, suite_id, hint, slot_padding)
        Native.sha256(
          AD_DOMAIN + header_hash + section_id + Binary.u16(index) +
            Binary.u16(suite_id) + hint + slot_padding
        )
      end
    end

    class RecipientSectionBuilder
      def initialize(recipients:, capacity:, slot_size:, payload_id:, header_hash:, dek:,
                     wrap_suite_id: WrapSuiteV1::ID)
        @recipients = recipients
        @capacity = capacity
        @slot_size = slot_size
        @payload_id = payload_id
        @header_hash = header_hash
        @dek = dek
        @wrap_suite_id = wrap_suite_id
      end

      def call
        section_id = Native.random_bytes(Format::SECTION_ID_BYTES)
        slots = real_slots(section_id)
        slots.concat(dummy_slots(section_id, slots.length))
        Binary.u16(@wrap_suite_id) + section_id + slots.join
      end

      private

      def real_slots(section_id)
        @recipients.each_with_index.map do |public_key, index|
          build_slot(public_key, @dek, index, section_id)
        end
      end

      def dummy_slots(section_id, first_index)
        (first_index...@capacity).map { |index| build_dummy_slot(index, section_id) }
      end

      def build_dummy_slot(index, section_id)
        pair = PQCrypto::HybridKEM.generate(WRAP_KEM_ALGORITHM)
        dummy_dek = Native.random_bytes(Format::DEK_BYTES)
        build_slot(pair.public_key, dummy_dek, index, section_id)
      ensure
        pair.secret_key.wipe! if pair && pair.secret_key.respond_to?(:wipe!)
        Secrets.wipe!(dummy_dek)
      end

      def build_slot(public_key, dek, index, section_id)
        KeyMaterial.validate_public_key!(public_key)
        hint = WrapSuiteV1.recipient_hint(public_key, @payload_id, section_id, @wrap_suite_id)
        encapsulation = KeyMaterial.assert_encapsulation!(public_key.encapsulate)
        nonce = Native.random_bytes(Format::NONCE_BYTES)
        padding = Native.random_bytes(@slot_size - Format::STANZA_BYTES)
        ad = WrapSuiteV1.associated_data(
          @header_hash, section_id, index, @wrap_suite_id, hint, padding
        )
        kek = WrapSuiteV1.derive_kek(
          encapsulation.shared_secret, @payload_id, section_id, @wrap_suite_id, index
        )
        wrapped, tag = Native.aegis256_encrypt(kek, nonce, ad, dek)
        hint + encapsulation.ciphertext + nonce + wrapped + tag + padding
      ensure
        Secrets.wipe!(kek)
        Secrets.wipe!(encapsulation.shared_secret) if encapsulation
      end
    end

    class RecipientSectionOpener
      SLOT_FAILURES = [PQCrypto::Error, AuthenticationError, ArgumentError, FormatError].freeze

      def initialize(header, section, credentials)
        @header = header
        @section = section
        @secret_key, @public_key = KeyMaterial.credentials(credentials)
        @header_hash = Native.sha256(header.raw)
        @expected_hint = WrapSuiteV1.recipient_hint(
          @public_key, header.payload_id, section.section_id, section.wrap_suite_id
        )
      end

      def call
        candidates = []
        matching_indexes.each do |index|
          candidate = try_open(index)
          candidates << candidate if candidate
        end
        return candidates.first if candidates.one?

        raise RecipientNotFoundError, "no matching recipient stanza" if candidates.empty?

        candidates.each { |candidate| Secrets.wipe!(candidate) }
        raise AmbiguousRecipientStanzas, "multiple recipient stanzas opened"
      ensure
        candidates.each { |candidate| Secrets.wipe!(candidate) } if $! && candidates
      end

      private

      def matching_indexes
        (0...@header.recipient_capacity).select do |index|
          Native.secure_equal(slot_hint(index), @expected_hint)
        end
      end

      def slot_hint(index)
        slot(index).byteslice(0, Format::HINT_BYTES)
      end

      def slot(index)
        @section.raw.byteslice(
          @section.slots_offset + index * @header.slot_size,
          @header.slot_size
        )
      end

      def try_open(index)
        fields = Format.split_slot(slot(index), @header.slot_size)
        ad = WrapSuiteV1.associated_data(
          @header_hash, @section.section_id, index, @section.wrap_suite_id,
          fields[:hint], fields[:padding]
        )
        shared = KeyMaterial.assert_shared_secret!(@secret_key.decapsulate(fields[:kem_ciphertext]))
        kek = WrapSuiteV1.derive_kek(
          shared, @header.payload_id, @section.section_id, @section.wrap_suite_id, index
        )
        Native.aegis256_decrypt(
          kek, fields[:wrap_nonce], ad, fields[:wrapped_dek], fields[:wrap_tag]
        )
      rescue *SLOT_FAILURES
        nil
      ensure
        Secrets.wipe_each!(shared, kek)
      end
    end
  end
end

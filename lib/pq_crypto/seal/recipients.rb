# frozen_string_literal: true

module PQCrypto
  module Seal
    WRAP_KEM_ALGORITHM = :ml_kem_768_x25519_xwing

    module KeyMaterial
      module_function

      def public_keys(value)
        keys = recipient_list(value)
        raise InvalidConfigurationError, 'at least one recipient is required' if keys.empty?

        reject_duplicates!(keys.map { |key| validate_public_key!(key) })
      end

      def credentials(value)
        secret_key, public_key = unpack_credentials(value)
        validate_secret_key!(secret_key)
        validate_public_key!(public_key, 'credential public key is invalid')
        [secret_key, public_key]
      end

      def build_credentials(secret_key:, public_key:)
        Credentials.new(secret_key: secret_key, public_key: public_key).tap { |pair| credentials(pair) }.freeze
      end

      def validate_public_key!(key, message = recipient_error)
        valid = key.is_a?(PQCrypto::HybridKEM::PublicKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, message unless valid

        assert_size!('X-Wing public key', key.to_bytes, Format::XWING_PUBLIC_KEY_BYTES)
        key
      end

      def validate_secret_key!(key)
        valid = key.is_a?(PQCrypto::HybridKEM::SecretKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, 'credential secret key is invalid' unless valid

        key
      end

      def assert_encapsulation!(encapsulation)
        assert_size!('X-Wing ciphertext', encapsulation.ciphertext, Format::XWING_CIPHERTEXT_BYTES)
        assert_size!('X-Wing shared secret', encapsulation.shared_secret, Format::XWING_SHARED_SECRET_BYTES)
        encapsulation
      end

      def assert_shared_secret!(secret)
        return secret if secret.bytesize == Format::XWING_SHARED_SECRET_BYTES

        raise FormatError, 'X-Wing shared secret has an invalid length'
      end

      def assert_size!(label, bytes, expected)
        actual = bytes.bytesize
        return bytes if actual == expected

        raise InvalidConfigurationError, "#{label} must be #{expected} bytes, got #{actual}"
      end

      def unpack_credentials(value)
        pair = credential_pair(value)
        return pair if pair.length == 2

        raise InvalidConfigurationError, credential_error
      end

      def credential_pair(value)
        case value
        when PQCrypto::HybridKEM::Keypair, Credentials then [value.secret_key, value.public_key]
        when Array then value
        else []
        end
      end

      def recipient_list(value)
        value.is_a?(Array) ? value : [value]
      end

      def reject_duplicates!(keys)
        fingerprints = keys.map { |key| Native.sha256(key.to_bytes) }
        return keys if fingerprints.uniq.length == fingerprints.length

        raise InvalidConfigurationError, 'recipient list contains duplicate public keys'
      end

      def recipient_error
        "recipient must be an X-Wing public key (#{WRAP_KEM_ALGORITHM})"
      end

      def credential_error
        'with: must be a HybridKEM::Keypair, Seal.credentials(...), or [secret_key, public_key]'
      end

      private_class_method :unpack_credentials, :credential_pair, :recipient_list, :reject_duplicates!,
                           :recipient_error, :credential_error
    end

    module WrapSuite
      HINT_DOMAIN = "PQC-SEAL-V1-RECIPIENT-HINT\0".b.freeze
      KEY_DOMAIN = "PQC-SEAL-V1-WRAP-KEY\0".b.freeze
      AD_DOMAIN = "PQC-SEAL-V1-WRAP-AD\0".b.freeze
      ID = Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256

      Binding = Struct.new(:payload_id, :section_id, :suite_id, :header_hash, keyword_init: true) do
        def recipient_hint(public_key)
          Native.sha256(HINT_DOMAIN + payload_id + section_id + Binary.u16(suite_id) + public_key.to_bytes)
        end

        def derive_kek(shared_secret, index)
          info = KEY_DOMAIN + payload_id + section_id + Binary.u16(suite_id) + Binary.u16(index)
          Native.hkdf_sha256(shared_secret, info, Format::DEK_BYTES)
        end

        def associated_data(index, hint, slot_padding)
          parts = [AD_DOMAIN, header_hash, section_id, Binary.u16(index), Binary.u16(suite_id), hint, slot_padding]
          Native.sha256(parts.join)
        end
      end
    end

    SectionSpec = Struct.new(:capacity, :slot_size, :payload_id, :header_hash, keyword_init: true) do
      def self.for_header(header, header_hash)
        new(
          capacity: header.recipient_capacity, slot_size: header.slot_size,
          payload_id: header.payload_id, header_hash: header_hash
        )
      end

      def binding(section_id)
        WrapSuite::Binding.new(
          payload_id: payload_id, section_id: section_id, suite_id: WrapSuite::ID, header_hash: header_hash
        )
      end
    end

    Stanza = Struct.new(:binding, :index, :hint) do
      def associated_data(slot_padding)
        binding.associated_data(index, hint, slot_padding)
      end

      def with_kek(shared_secret)
        kek = binding.derive_kek(shared_secret, index)
        yield kek
      ensure
        Secrets.wipe!(kek)
      end

      def seal(shared_secret, dek, padding_length)
        nonce = Native.random_bytes(Format::NONCE_BYTES)
        padding = Native.random_bytes(padding_length)
        sealed = with_kek(shared_secret) { |kek| Native.aegis256_encrypt(kek, nonce, associated_data(padding), dek) }
        nonce + sealed.join + padding
      end
    end

    SealedStanza = Struct.new(:hint, :kem_ciphertext, :wrap_nonce, :wrapped_dek, :wrap_tag, :padding,
                              keyword_init: true) do
      def self.parse(slot)
        new(**Format.split_slot(slot))
      end

      def unwrap(stanza, shared_secret)
        associated_data = stanza.associated_data(padding)
        stanza.with_kek(shared_secret) do |kek|
          Native.aegis256_decrypt(kek, wrap_nonce, associated_data, wrapped_dek, wrap_tag)
        end
      end
    end

    class StanzaSealer
      def initialize(binding, slot_size)
        @wrap_binding = binding
        @slot_size = slot_size
      end

      def seal(public_key, dek, index)
        KeyMaterial.validate_public_key!(public_key)
        stanza = Stanza.new(wrap_binding, index, wrap_binding.recipient_hint(public_key))
        encapsulation = public_key.encapsulate
        KeyMaterial.assert_encapsulation!(encapsulation)
        stanza.hint + encapsulation.ciphertext +
          stanza.seal(encapsulation.shared_secret, dek, slot_size - Format::STANZA_BYTES)
      ensure
        Secrets.wipe!(encapsulation&.shared_secret)
      end

      def seal_decoy(index)
        pair = PQCrypto::HybridKEM.generate(WRAP_KEM_ALGORITHM)
        decoy_dek = Native.random_bytes(Format::DEK_BYTES)
        seal(pair.public_key, decoy_dek, index)
      ensure
        pair&.secret_key&.wipe!
        Secrets.wipe!(decoy_dek)
      end

      def section(slots)
        Binary.u16(wrap_binding.suite_id) + wrap_binding.section_id + slots.join
      end

      private

      attr_reader :wrap_binding, :slot_size
    end

    class RecipientSectionBuilder
      def initialize(spec, recipients, dek)
        @spec = spec
        @recipients = recipients
        @dek = dek
      end

      def call
        sealer = StanzaSealer.new(spec.binding(Native.random_bytes(Format::SECTION_ID_BYTES)), spec.slot_size)
        sealer.section(recipient_slots(sealer) + decoy_slots(sealer))
      end

      private

      attr_reader :spec, :recipients, :dek

      def recipient_slots(sealer)
        recipients.map.with_index { |public_key, index| sealer.seal(public_key, dek, index) }
      end

      def decoy_slots(sealer)
        (recipients.length...spec.capacity).map { |index| sealer.seal_decoy(index) }
      end
    end

    class SlotTable
      attr_reader :binding

      def initialize(header, section)
        @header = header
        @section = section
        @binding = WrapSuite::Binding.new(
          payload_id: header.payload_id, section_id: section.section_id,
          suite_id: section.wrap_suite_id, header_hash: Native.sha256(header.raw)
        )
      end

      def indexes
        0...header.recipient_capacity
      end

      def slot(index)
        size = header.slot_size
        section.raw.byteslice(section.slots_offset + (index * size), size)
      end

      private

      attr_reader :header, :section
    end

    class RecipientSectionOpener
      SLOT_FAILURES = [PQCrypto::Error, AuthenticationError, ArgumentError, FormatError].freeze

      def initialize(header, section, credentials)
        @slots = SlotTable.new(header, section)
        @secret_key, public_key = KeyMaterial.credentials(credentials)
        @expected_hint = slots.binding.recipient_hint(public_key)
      end

      def call
        candidates = open_candidates
        return candidates.first if candidates.one?

        Secrets.wipe_each!(candidates)
        raise RecipientNotFoundError, 'no matching recipient stanza' if candidates.empty?

        raise AmbiguousRecipientStanzas, 'multiple recipient stanzas opened'
      end

      private

      attr_reader :slots, :secret_key, :expected_hint

      def open_candidates
        opened = []
        matching_indexes.each_with_object(opened) { |index, candidates| candidates << try_open(index) }
        candidates = opened.compact
      ensure
        Secrets.wipe_each!(opened) unless candidates
      end

      def matching_indexes
        slots.indexes.select do |index|
          Native.secure_equal(slots.slot(index).byteslice(0, Format::HINT_BYTES), expected_hint)
        end
      end

      def try_open(index)
        sealed = SealedStanza.parse(slots.slot(index))
        shared = secret_key.decapsulate(sealed.kem_ciphertext)
        KeyMaterial.assert_shared_secret!(shared)
        sealed.unwrap(Stanza.new(slots.binding, index, sealed.hint), shared)
      rescue *SLOT_FAILURES
        nil
      ensure
        Secrets.wipe!(shared)
      end
    end
  end
end

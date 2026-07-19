# frozen_string_literal: true

module PQCrypto
  module Seal
    Opened = Struct.new(:data, :metadata, :public_metadata, :payload_id, :content_suite_id, :wrap_suite_id,
                        :padding_policy_id, keyword_init: true) do
      def self.from_header(header, section, data:, metadata:)
        new(
          data: data, metadata: metadata, public_metadata: header.public_metadata,
          payload_id: header.payload_id, content_suite_id: header.content_suite_id,
          wrap_suite_id: section.wrap_suite_id, padding_policy_id: header.padding_policy_id
        )
      end
    end

    Inspection = Struct.new(:payload_id, :public_metadata, :recipient_capacity, :slot_size,
                            :padded_inner_length, :content_suite_id, :wrap_suite_id,
                            :padding_policy_id, :envelope_bytes, keyword_init: true) do
      def self.from_header(header, section, envelope_bytes:)
        new(
          payload_id: header.payload_id, public_metadata: header.public_metadata,
          recipient_capacity: header.recipient_capacity, slot_size: header.slot_size,
          padded_inner_length: header.padded_inner_length,
          content_suite_id: header.content_suite_id, wrap_suite_id: section.wrap_suite_id,
          padding_policy_id: header.padding_policy_id, envelope_bytes: envelope_bytes
        )
      end
    end
    Credentials = Struct.new(:secret_key, :public_key, keyword_init: true)

    WRAP_KEM_ALGORITHM = :ml_kem_768_x25519_xwing
    HINT_DOMAIN = "PQC-SEAL-V1-RECIPIENT-HINT\0".b
    WRAP_KEY_DOMAIN = "PQC-SEAL-V1-WRAP-KEY\0".b
    WRAP_AD_DOMAIN = "PQC-SEAL-V1-WRAP-AD\0".b

    module_function

    def credentials(secret_key:, public_key:)
      validate_secret_key!(secret_key)
      normalize_public_keys(public_key)
      Credentials.new(secret_key: secret_key, public_key: public_key).freeze
    end

    def encrypt(data, to:, metadata: "".b, public_metadata: "".b,
                recipient_capacity: Format::DEFAULT_RECIPIENT_CAPACITY,
                slot_size: Format::DEFAULT_SLOT_SIZE, padding: :padme)
      data = String(data).b
      metadata = String(metadata).b
      validate_private_metadata!(metadata)
      recipients = normalize_public_keys(to)
      capacity = Format.validate_capacity!(recipient_capacity, recipients.length)
      slot_size = Format.validate_slot_size!(slot_size)

      parts = nil
      pad_bytes = nil
      inner = nil
      parts = materialize_crypto_parts(
        recipients: recipients, capacity: capacity, slot_size: slot_size,
        padding: padding, public_metadata: public_metadata,
        content_size: data.bytesize, metadata_size: metadata.bytesize
      )
      pad_bytes = Native.random_bytes(parts[:padded_inner_length] - parts[:raw_inner_length])
      inner = parts[:inner_prefix] + metadata + data + pad_bytes
      ciphertext, tag = Native.aegis256_encrypt(parts[:dek], parts[:payload_nonce], parts[:header_hash], inner)
      parts[:header] + parts[:section] + ciphertext + tag
    ensure
      wipe_string!(parts[:dek]) if parts
      wipe_string!(inner)
      wipe_string!(pad_bytes)
      wipe_string!(metadata) if metadata.is_a?(String) && !metadata.frozen?
      wipe_string!(data) if data.is_a?(String) && !data.frozen?
    end

    def decrypt(envelope, with:, **limits)
      open(envelope, with: with, **limits).data
    end

    def open(envelope, with:, **limits)
      limits = Format::LIMIT_DEFAULTS.merge(limits)
      bytes = String(envelope).b
      Format.check_resource_limits!(
        padded_inner_length: 0, envelope_bytes: bytes.bytesize, **Format.pre_auth_limits(limits)
      )
      header, section, ciphertext, tag = parse_envelope(bytes)
      Format.check_resource_limits!(
        padded_inner_length: header.padded_inner_length,
        envelope_bytes: bytes.bytesize, **Format.pre_auth_limits(limits)
      )
      dek = unwrap_dek(header, section, with)
      header_hash = Native.sha256(header.raw)
      inner = Native.aegis256_decrypt(dek, header.payload_nonce, header_hash, ciphertext, tag)
      content, metadata, = Format.parse_verified_inner(inner)
      enforce_plaintext_limit!(content, metadata, limits[:max_plaintext_bytes])
      Opened.from_header(header, section, data: content, metadata: metadata)
    ensure
      wipe_string!(dek) if defined?(dek)
      wipe_string!(inner) if defined?(inner)
    end

    def inspect_envelope(envelope)
      bytes = String(envelope).b
      header, section, = parse_envelope(bytes)
      Inspection.from_header(header, section, envelope_bytes: bytes.bytesize)
    end

    def digest(envelope)
      Native.sha256(String(envelope).b)
    end

    def rebuild_recipients(envelope, with:, recipients:)
      bytes = String(envelope).b
      header, section, ciphertext, tag = parse_envelope(bytes)
      dek = unwrap_dek(header, section, with)
      verify_payload!(header, ciphertext, tag, dek)
      public_keys = normalize_public_keys(recipients)
      Format.validate_capacity!(header.recipient_capacity, public_keys.length)
      new_section = build_recipient_section(
        recipients: public_keys, capacity: header.recipient_capacity,
        slot_size: header.slot_size, payload_id: header.payload_id,
        header_hash: Native.sha256(header.raw), dek: dek,
        wrap_suite_id: Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
      )
      header.raw + new_section + ciphertext + tag
    ensure
      wipe_string!(dek) if defined?(dek)
    end

    def add_recipient(envelope, with:, recipient:, current_recipients:)
      rebuild_recipients(envelope, with: with, recipients: Array(current_recipients) + [recipient])
    end

    def drop_recipient_stanza(envelope, with:, remaining_recipients:)
      rebuild_recipients(envelope, with: with, recipients: remaining_recipients)
    end

    def rotate_dek(envelope, with:, recipients:, padding: :preserve)
      bytes = String(envelope).b
      header, section, ciphertext, tag = parse_envelope(bytes)
      dek = unwrap_dek(header, section, with)
      header_hash = Native.sha256(header.raw)
      inner = Native.aegis256_decrypt(dek, header.payload_nonce, header_hash, ciphertext, tag)
      content, metadata, = Format.parse_verified_inner(inner)
      padding = { to: bytes.bytesize } if padding == :preserve
      encrypt(
        content, to: recipients, metadata: metadata,
        public_metadata: header.public_metadata,
        recipient_capacity: header.recipient_capacity,
        slot_size: header.slot_size, padding: padding
      )
    ensure
      wipe_string!(dek) if defined?(dek)
      wipe_string!(inner) if defined?(inner)
      wipe_string!(content) if defined?(content)
      wipe_string!(metadata) if defined?(metadata)
    end

    def materialize_crypto_parts(recipients:, capacity:, slot_size:, padding:, public_metadata:,
                                 content_size:, metadata_size:)
      padding_policy_id = Format.padding_policy_id_for(padding)
      payload_id = Native.random_bytes(Format::PAYLOAD_ID_BYTES)
      payload_nonce = Native.random_bytes(Format::NONCE_BYTES)
      dek = Native.random_bytes(Format::DEK_BYTES)
      inner_prefix = Format.inner_prefix(content_size, metadata_size)
      raw_inner_length = inner_prefix.bytesize + metadata_size + content_size

      placeholder = Format.build_header(
        payload_id: payload_id, payload_nonce: payload_nonce,
        recipient_capacity: capacity, slot_size: slot_size,
        padded_inner_length: raw_inner_length, public_metadata: public_metadata,
        padding_policy_id: padding_policy_id
      )
      fixed = placeholder.bytesize + Format.section_length_for(capacity, slot_size) + Format::TAG_BYTES
      target = Padding.target(fixed + raw_inner_length, padding)
      padded_inner_length = target - fixed
      raise InvalidConfigurationError, "invalid padding target" if padded_inner_length < raw_inner_length

      header = Format.build_header(
        payload_id: payload_id, payload_nonce: payload_nonce,
        recipient_capacity: capacity, slot_size: slot_size,
        padded_inner_length: padded_inner_length, public_metadata: public_metadata,
        padding_policy_id: padding_policy_id
      )
      header_hash = Native.sha256(header)
      section = build_recipient_section(
        recipients: recipients, capacity: capacity, slot_size: slot_size,
        payload_id: payload_id, header_hash: header_hash, dek: dek,
        wrap_suite_id: Format::WRAP_SUITE_MLKEM768_X25519_AEGIS256
      )
      {
        header: header, section: section, dek: dek, payload_id: payload_id,
        payload_nonce: payload_nonce, header_hash: header_hash,
        inner_prefix: inner_prefix, raw_inner_length: raw_inner_length,
        padded_inner_length: padded_inner_length
      }
    end

    def enforce_plaintext_limit!(content, metadata, max_plaintext_bytes)
      return if content.bytesize <= Integer(max_plaintext_bytes)
      wipe_string!(content)
      wipe_string!(metadata)
      raise ResourceLimitError,
            "plaintext #{content.bytesize} exceeds max_plaintext_bytes #{max_plaintext_bytes}"
    end

    def verify_payload!(header, ciphertext, tag, dek)
      verified = Native.aegis256_decrypt(
        dek, header.payload_nonce, Native.sha256(header.raw), ciphertext, tag
      )
      true
    ensure
      wipe_string!(verified) if defined?(verified)
    end

    def parse_envelope(bytes)
      header = Format.parse_header(bytes)
      section_offset = header.raw.bytesize
      section = Format.parse_section(bytes, section_offset, header)
      payload_offset = section_offset + section.raw.bytesize
      expected = payload_offset + header.padded_inner_length + Format::TAG_BYTES
      raise FormatError, "envelope length does not match header" unless bytes.bytesize == expected
      ciphertext = bytes.byteslice(payload_offset, header.padded_inner_length).b
      tag = bytes.byteslice(payload_offset + header.padded_inner_length, Format::TAG_BYTES).b
      [header, section, ciphertext, tag]
    end

    def build_recipient_section(recipients:, capacity:, slot_size:, payload_id:, header_hash:, dek:, wrap_suite_id:)
      section_id = Native.random_bytes(Format::SECTION_ID_BYTES)
      slots = recipients.each_with_index.map do |public_key, index|
        build_slot(public_key, index, slot_size, payload_id, section_id, header_hash, dek, wrap_suite_id)
      end
      (slots.length...capacity).each do |index|
        dummy_pair = nil
        dummy_dek = nil
        begin
          dummy_pair = PQCrypto::HybridKEM.generate(WRAP_KEM_ALGORITHM)
          dummy_dek = Native.random_bytes(Format::DEK_BYTES)
          slots << build_slot(dummy_pair.public_key, index, slot_size, payload_id, section_id, header_hash, dummy_dek, wrap_suite_id)
        ensure
          dummy_pair.secret_key.wipe! if dummy_pair && dummy_pair.secret_key.respond_to?(:wipe!)
          wipe_string!(dummy_dek)
        end
      end
      Binary.u16(wrap_suite_id) + section_id + slots.join
    end

    def build_slot(public_key, index, slot_size, payload_id, section_id, header_hash, dek, wrap_suite_id)
      assert_xwing_public_key!(public_key)
      hint = recipient_hint(public_key, payload_id, section_id, wrap_suite_id)
      encapsulated = public_key.encapsulate
      assert_xwing_encapsulation!(encapsulated)
      wrap_nonce = Native.random_bytes(Format::NONCE_BYTES)
      slot_padding = Native.random_bytes(slot_size - Format::STANZA_BYTES)
      slot_ad = wrap_ad(header_hash, section_id, index, wrap_suite_id, hint, slot_padding)
      kek = derive_kek(encapsulated.shared_secret, payload_id, section_id, wrap_suite_id, index)
      wrapped, tag = Native.aegis256_encrypt(kek, wrap_nonce, slot_ad, dek)
      hint + encapsulated.ciphertext + wrap_nonce + wrapped + tag + slot_padding
    ensure
      wipe_string!(kek) if defined?(kek)
      wipe_string!(encapsulated.shared_secret) if defined?(encapsulated) && encapsulated
    end

    def unwrap_dek(header, section, secret_key)
      secret_key, public_key = normalize_credentials(secret_key)
      assert_xwing_public_key!(public_key)
      expected_hint = recipient_hint(public_key, header.payload_id, section.section_id, section.wrap_suite_id)
      header_hash = Native.sha256(header.raw)
      successes = []

      header.recipient_capacity.times do |index|
        slot = section.raw.byteslice(section.slots_offset + index * header.slot_size, header.slot_size)
        hint = slot.byteslice(0, Format::HINT_BYTES)
        next unless secure_equal?(hint, expected_hint)

        begin
          fields = Format.split_slot(slot, header.slot_size)
          slot_ad = wrap_ad(header_hash, section.section_id, index, section.wrap_suite_id, hint, fields[:padding])
          shared = secret_key.decapsulate(fields[:kem_ciphertext])
          assert_size!("X-Wing shared secret", shared.bytesize, Format::XWING_SHARED_SECRET_BYTES, FormatError)
          kek = derive_kek(shared, header.payload_id, section.section_id, section.wrap_suite_id, index)
          successes << Native.aegis256_decrypt(kek, fields[:wrap_nonce], slot_ad, fields[:wrapped_dek], fields[:wrap_tag])
        rescue PQCrypto::Error, AuthenticationError, ArgumentError, FormatError
        ensure
          wipe_string!(shared) if defined?(shared)
          wipe_string!(kek) if defined?(kek)
        end
      end

      raise RecipientNotFoundError, "no matching recipient stanza" if successes.empty?
      if successes.length != 1
        successes.each { |candidate| wipe_string!(candidate) }
        raise AmbiguousRecipientStanzas, "multiple recipient stanzas opened"
      end
      successes.first
    end

    def recipient_hint(public_key, payload_id, section_id, wrap_suite_id)
      Native.sha256(HINT_DOMAIN + payload_id + section_id + Binary.u16(wrap_suite_id) + public_key.to_bytes)
    end

    def wrap_ad(header_hash, section_id, index, wrap_suite_id, hint, slot_padding)
      Native.sha256(
        WRAP_AD_DOMAIN + header_hash + section_id + Binary.u16(index) +
          Binary.u16(wrap_suite_id) + hint + slot_padding
      )
    end

    def derive_kek(shared_secret, payload_id, section_id, wrap_suite_id, index)
      info = WRAP_KEY_DOMAIN + payload_id + section_id + Binary.u16(wrap_suite_id) + Binary.u16(index)
      Native.hkdf_sha256(shared_secret, info, Format::DEK_BYTES)
    end

    def assert_size!(label, actual, expected, error = InvalidConfigurationError)
      return if actual == expected
      raise error, "#{label} must be #{expected} bytes, got #{actual}"
    end

    def assert_xwing_public_key!(public_key)
      assert_size!("X-Wing public key", public_key.to_bytes.bytesize, Format::XWING_PUBLIC_KEY_BYTES)
    end

    def assert_xwing_encapsulation!(encapsulated)
      assert_size!("X-Wing ciphertext", encapsulated.ciphertext.bytesize, Format::XWING_CIPHERTEXT_BYTES)
      assert_size!("X-Wing shared secret", encapsulated.shared_secret.bytesize, Format::XWING_SHARED_SECRET_BYTES)
    end

    def normalize_public_keys(value)
      keys = value.is_a?(Array) ? value : [value]
      raise InvalidConfigurationError, "at least one recipient is required" if keys.empty?
      keys.each { |key| validate_public_key!(key, "recipient must be an X-Wing public key (#{WRAP_KEM_ALGORITHM})") }
      fingerprints = keys.map { |key| Native.sha256(key.to_bytes) }
      if fingerprints.uniq.length != fingerprints.length
        raise InvalidConfigurationError, "recipient list contains duplicate public keys"
      end
      keys
    end

    def normalize_credentials(value)
      secret_key, public_key = credential_pair(value)
      validate_secret_key!(secret_key)
      validate_public_key!(public_key, "credential public key is invalid")
      [secret_key, public_key]
    end

    def credential_pair(value)
      case value
      when PQCrypto::HybridKEM::Keypair then [value.secret_key, value.public_key]
      when Credentials then [value.secret_key, value.public_key]
      when Array
        unless value.length == 2
          raise InvalidConfigurationError,
                "with: must be a HybridKEM::Keypair, Seal.credentials(...), or [secret_key, public_key]"
        end
        value
      else
        raise InvalidConfigurationError,
              "with: must be a HybridKEM::Keypair, Seal.credentials(...), or [secret_key, public_key]"
      end
    end

    def validate_public_key!(key, message)
      unless key.is_a?(PQCrypto::HybridKEM::PublicKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, message
      end
      assert_xwing_public_key!(key)
    end

    def validate_secret_key!(key)
      unless key.is_a?(PQCrypto::HybridKEM::SecretKey) && key.algorithm == WRAP_KEM_ALGORITHM
        raise InvalidConfigurationError, "credential secret key is invalid"
      end
    end

    def validate_private_metadata!(metadata)
      if metadata.bytesize > Format::MAX_PRIVATE_METADATA_BYTES
        raise InvalidConfigurationError, "private metadata is too large"
      end
    end

    def secure_equal?(a, b)
      return false unless a && b && a.bytesize == b.bytesize
      Native.secure_equal(a, b)
    end

    def wipe_string!(value)
      return unless value.is_a?(String) && !value.frozen?
      value.replace("\0".b * value.bytesize)
    rescue StandardError
      nil
    end

    public_api = %i[
      credentials encrypt decrypt open inspect_envelope digest
      rebuild_recipients add_recipient drop_recipient_stanza rotate_dek
    ]
    private_names = singleton_methods(false).map(&:to_sym) - public_api
    private_class_method(*private_names) unless private_names.empty?
  end
end

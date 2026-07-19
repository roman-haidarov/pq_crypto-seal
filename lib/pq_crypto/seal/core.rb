# frozen_string_literal: true

module PQCrypto
  module Seal
    Opened = Struct.new(:data, :metadata, :public_metadata, :payload_id, :content_suite_id, :wrap_suite_id,
                        :padding_policy_id, keyword_init: true)
    Inspection = Struct.new(:payload_id, :public_metadata, :recipient_capacity, :slot_size,
                            :padded_inner_length, :content_suite_id, :wrap_suite_id,
                            :padding_policy_id, :envelope_bytes, keyword_init: true)
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
      padding_policy_id = Format.padding_policy_id_for(padding)

      payload_id = Native.random_bytes(Format::PAYLOAD_ID_BYTES)
      payload_nonce = Native.random_bytes(Format::NONCE_BYTES)
      dek = Native.random_bytes(Format::DEK_BYTES)
      inner_prefix = Format.inner_prefix(data.bytesize, metadata.bytesize)
      raw_inner_length = inner_prefix.bytesize + metadata.bytesize + data.bytesize

      header_placeholder = Format.build_header(
        payload_id: payload_id, payload_nonce: payload_nonce,
        recipient_capacity: capacity, slot_size: slot_size,
        padded_inner_length: raw_inner_length, public_metadata: public_metadata,
        padding_policy_id: padding_policy_id
      )
      fixed_without_inner = header_placeholder.bytesize + Format.section_length_for(capacity, slot_size) + Format::TAG_BYTES
      target = Padding.target(fixed_without_inner + raw_inner_length, padding)
      padded_inner_length = target - fixed_without_inner
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
      pad_length = padded_inner_length - raw_inner_length
      pad_bytes = Native.random_bytes(pad_length)
      inner = inner_prefix + metadata + data + pad_bytes
      ciphertext, tag = Native.aegis256_encrypt(dek, payload_nonce, header_hash, inner)
      header + section + ciphertext + tag
    ensure
      wipe_string!(dek) if defined?(dek)
      wipe_string!(inner) if defined?(inner)
      wipe_string!(pad_bytes) if defined?(pad_bytes)
      wipe_string!(metadata) if defined?(metadata) && metadata.is_a?(String) && !metadata.frozen?
    end

    def decrypt(envelope, with:,
                max_staging_bytes: Format::DEFAULT_MAX_STAGING_BYTES,
                max_plaintext_bytes: Format::DEFAULT_MAX_PLAINTEXT_BYTES,
                max_envelope_bytes: Format::DEFAULT_MAX_ENVELOPE_BYTES)
      open(envelope, with: with,
           max_staging_bytes: max_staging_bytes,
           max_plaintext_bytes: max_plaintext_bytes,
           max_envelope_bytes: max_envelope_bytes).data
    end

    def open(envelope, with:,
             max_staging_bytes: Format::DEFAULT_MAX_STAGING_BYTES,
             max_plaintext_bytes: Format::DEFAULT_MAX_PLAINTEXT_BYTES,
             max_envelope_bytes: Format::DEFAULT_MAX_ENVELOPE_BYTES)
      bytes = String(envelope).b
      Format.check_resource_limits!(
        padded_inner_length: 0, envelope_bytes: bytes.bytesize,
        max_staging_bytes: max_staging_bytes,
        max_plaintext_bytes: max_plaintext_bytes,
        max_envelope_bytes: max_envelope_bytes
      )
      header, section, ciphertext, tag = parse_envelope(bytes)
      Format.check_resource_limits!(
        padded_inner_length: header.padded_inner_length,
        envelope_bytes: bytes.bytesize,
        max_staging_bytes: max_staging_bytes,
        max_plaintext_bytes: max_plaintext_bytes,
        max_envelope_bytes: max_envelope_bytes
      )
      dek = unwrap_dek(header, section, with)
      header_hash = Native.sha256(header.raw)
      inner = Native.aegis256_decrypt(dek, header.payload_nonce, header_hash, ciphertext, tag)
      content, metadata, = Format.parse_verified_inner(inner)
      if content.bytesize > Integer(max_plaintext_bytes)
        wipe_string!(content)
        wipe_string!(metadata)
        raise ResourceLimitError,
              "plaintext #{content.bytesize} exceeds max_plaintext_bytes #{max_plaintext_bytes}"
      end
      Opened.new(
        data: content, metadata: metadata, public_metadata: header.public_metadata,
        payload_id: header.payload_id, content_suite_id: header.content_suite_id,
        wrap_suite_id: section.wrap_suite_id, padding_policy_id: header.padding_policy_id
      )
    ensure
      wipe_string!(dek) if defined?(dek)
      wipe_string!(inner) if defined?(inner)
    end

    def inspect_envelope(envelope)
      bytes = String(envelope).b
      header, section, = parse_envelope(bytes)
      Inspection.new(
        payload_id: header.payload_id, public_metadata: header.public_metadata,
        recipient_capacity: header.recipient_capacity, slot_size: header.slot_size,
        padded_inner_length: header.padded_inner_length,
        content_suite_id: header.content_suite_id, wrap_suite_id: section.wrap_suite_id,
        padding_policy_id: header.padding_policy_id,
        envelope_bytes: bytes.bytesize
      )
    end

    def digest(envelope)
      Native.sha256(String(envelope).b)
    end

    # Rebuilds every real and dummy stanza while leaving the encrypted payload untouched.
    # The caller must provide the complete authoritative recipient list.
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
      rebuild_recipients(
        envelope, with: with,
        recipients: Array(current_recipients) + [recipient]
      )
    end

    def drop_recipient_stanza(envelope, with:, remaining_recipients:)
      rebuild_recipients(envelope, with: with, recipients: remaining_recipients)
    end

    def rotate_dek(envelope, with:, recipients:, padding: :preserve)
      bytes = String(envelope).b
      opened = open(bytes, with: with)
      info = inspect_envelope(bytes)
      padding = { to: info.envelope_bytes } if padding == :preserve
      encrypt(
        opened.data, to: recipients, metadata: opened.metadata,
        public_metadata: opened.public_metadata,
        recipient_capacity: info.recipient_capacity,
        slot_size: info.slot_size, padding: padding
      )
    ensure
      if defined?(opened) && opened
        wipe_string!(opened.data)
        wipe_string!(opened.metadata)
      end
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
      real_slots = recipients.each_with_index.map do |public_key, index|
        build_slot(public_key, index, slot_size, payload_id, section_id, header_hash, dek, wrap_suite_id)
      end
      (real_slots.length...capacity).each do |index|
        dummy_pair = nil
        dummy_dek = nil
        begin
          dummy_pair = PQCrypto::HybridKEM.generate(WRAP_KEM_ALGORITHM)
          dummy_dek = Native.random_bytes(Format::DEK_BYTES)
          real_slots << build_slot(dummy_pair.public_key, index, slot_size, payload_id, section_id, header_hash, dummy_dek, wrap_suite_id)
        ensure
          dummy_pair.secret_key.wipe! if dummy_pair && dummy_pair.secret_key.respond_to?(:wipe!)
          wipe_string!(dummy_dek)
        end
      end
      Binary.u16(wrap_suite_id) + section_id + real_slots.join
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
          offset = Format::HINT_BYTES
          kem_ct = slot.byteslice(offset, Format::XWING_CIPHERTEXT_BYTES); offset += Format::XWING_CIPHERTEXT_BYTES
          nonce = slot.byteslice(offset, Format::NONCE_BYTES); offset += Format::NONCE_BYTES
          wrapped = slot.byteslice(offset, Format::DEK_BYTES); offset += Format::DEK_BYTES
          tag = slot.byteslice(offset, Format::TAG_BYTES); offset += Format::TAG_BYTES
          slot_padding = slot.byteslice(offset, header.slot_size - offset)
          slot_ad = wrap_ad(header_hash, section.section_id, index, section.wrap_suite_id, hint, slot_padding)
          shared = secret_key.decapsulate(kem_ct)
          raise FormatError, "unexpected shared secret size" unless shared.bytesize == Format::XWING_SHARED_SECRET_BYTES
          kek = derive_kek(shared, header.payload_id, section.section_id, section.wrap_suite_id, index)
          successes << Native.aegis256_decrypt(kek, nonce, slot_ad, wrapped, tag)
        rescue PQCrypto::Error, AuthenticationError, ArgumentError, FormatError
          # All KEM, malformed-point, and AEAD failures are a nonmatching slot.
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

    def assert_xwing_public_key!(public_key)
      bytes = public_key.to_bytes
      unless bytes.bytesize == Format::XWING_PUBLIC_KEY_BYTES
        raise InvalidConfigurationError,
              "X-Wing public key must be #{Format::XWING_PUBLIC_KEY_BYTES} bytes, got #{bytes.bytesize}"
      end
    end

    def assert_xwing_encapsulation!(encapsulated)
      unless encapsulated.ciphertext.bytesize == Format::XWING_CIPHERTEXT_BYTES
        raise InvalidConfigurationError,
              "X-Wing ciphertext must be #{Format::XWING_CIPHERTEXT_BYTES} bytes, got #{encapsulated.ciphertext.bytesize}"
      end
      unless encapsulated.shared_secret.bytesize == Format::XWING_SHARED_SECRET_BYTES
        raise InvalidConfigurationError,
              "X-Wing shared secret must be #{Format::XWING_SHARED_SECRET_BYTES} bytes, got #{encapsulated.shared_secret.bytesize}"
      end
    end

    def normalize_public_keys(value)
      keys = value.is_a?(Array) ? value : [value]
      raise InvalidConfigurationError, "at least one recipient is required" if keys.empty?
      keys.each do |key|
        unless key.is_a?(PQCrypto::HybridKEM::PublicKey) && key.algorithm == WRAP_KEM_ALGORITHM
          raise InvalidConfigurationError, "recipient must be an X-Wing public key (#{WRAP_KEM_ALGORITHM})"
        end
        assert_xwing_public_key!(key)
      end
      fingerprints = keys.map { |key| Native.sha256(key.to_bytes) }
      if fingerprints.uniq.length != fingerprints.length
        raise InvalidConfigurationError, "recipient list contains duplicate public keys"
      end
      keys
    end

    def normalize_credentials(value)
      if value.is_a?(PQCrypto::HybridKEM::Keypair)
        validate_secret_key!(value.secret_key)
        unless value.public_key.is_a?(PQCrypto::HybridKEM::PublicKey) &&
               value.public_key.algorithm == WRAP_KEM_ALGORITHM
          raise InvalidConfigurationError, "credential public key is invalid"
        end
        return [value.secret_key, value.public_key]
      end
      if value.is_a?(Credentials)
        secret_key, public_key = value.secret_key, value.public_key
        validate_secret_key!(secret_key)
        unless public_key.is_a?(PQCrypto::HybridKEM::PublicKey) &&
               public_key.algorithm == WRAP_KEM_ALGORITHM
          raise InvalidConfigurationError, "credential public key is invalid"
        end
        return [secret_key, public_key]
      end
      if value.is_a?(Array) && value.length == 2
        secret_key, public_key = value
        validate_secret_key!(secret_key)
        unless public_key.is_a?(PQCrypto::HybridKEM::PublicKey) &&
               public_key.algorithm == WRAP_KEM_ALGORITHM
          raise InvalidConfigurationError, "credential public key is invalid"
        end
        return [secret_key, public_key]
      end
      raise InvalidConfigurationError,
            "with: must be a HybridKEM::Keypair, Seal.credentials(...), or [secret_key, public_key]"
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
    ].map(&:to_sym)
    private_names = singleton_methods(false).map(&:to_sym) - public_api
    private_class_method(*private_names) unless private_names.empty?
  end
end

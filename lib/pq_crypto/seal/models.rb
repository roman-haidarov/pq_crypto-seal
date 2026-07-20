# frozen_string_literal: true

module PQCrypto
  module Seal
    SHARED_ENVELOPE_ATTRS = lambda do |header, section|
      {
        public_metadata: header.public_metadata,
        payload_id: header.payload_id,
        content_suite_id: header.content_suite_id,
        wrap_suite_id: section.wrap_suite_id,
        padding_policy_id: header.padding_policy_id
      }
    end

    private_constant :SHARED_ENVELOPE_ATTRS

    Opened = Struct.new(
      :data, :metadata, :public_metadata, :payload_id,
      :content_suite_id, :wrap_suite_id, :padding_policy_id,
      keyword_init: true
    ) do
      def self.build(header, section, data:, metadata:)
        new(data: data, metadata: metadata, **SHARED_ENVELOPE_ATTRS.call(header, section))
      end
    end

    Inspection = Struct.new(
      :payload_id, :public_metadata, :recipient_capacity, :slot_size,
      :padded_inner_length, :content_suite_id, :wrap_suite_id,
      :padding_policy_id, :envelope_bytes,
      keyword_init: true
    ) do
      def self.build(header, section, envelope_bytes:)
        new(
          recipient_capacity: header.recipient_capacity,
          slot_size: header.slot_size,
          padded_inner_length: header.padded_inner_length,
          envelope_bytes: envelope_bytes,
          **SHARED_ENVELOPE_ATTRS.call(header, section)
        )
      end
    end

    Credentials = Struct.new(:secret_key, :public_key, keyword_init: true)
  end
end

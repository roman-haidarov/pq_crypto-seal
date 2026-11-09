# frozen_string_literal: true

require_relative 'test_helper'

class SealRecipientsTest < Minitest::Test
  include SealTestSupport

  DOCUMENT = SEAL.encrypt('document', to: ALICE.public_key, padding: :none)
  REBUILT = SEAL.rebuild_recipients(DOCUMENT, with: ALICE, recipients: [ALICE.public_key, BOB.public_key])
  LONG_TEXT = ('document' * 500).freeze
  TWO_SLOTS = SEAL.encrypt('ambig', to: ALICE.public_key, recipient_capacity: 2, slot_size: 2048, padding: :none)

  def test_rebuild_grants_access_to_new_recipients
    assert_equal 'document', SEAL.decrypt(REBUILT, with: BOB)
  end

  def test_rebuild_leaves_the_original_envelope_unchanged
    assert_raises(PQCrypto::Seal::RecipientNotFoundError) { SEAL.decrypt(DOCUMENT, with: BOB) }
  end

  def test_rebuild_keeps_the_payload_identity
    identifiers = [DOCUMENT, REBUILT].map { |envelope| SEAL.inspect_envelope(envelope).payload_id }
    assert_equal 1, identifiers.uniq.size
  end

  def test_rebuild_changes_the_envelope_digest
    refute_equal SEAL.digest(DOCUMENT), SEAL.digest(REBUILT)
  end

  def test_add_recipient_appends_to_the_current_list
    added = SEAL.add_recipient(DOCUMENT, with: ALICE, recipient: BOB.public_key, current_recipients: [ALICE.public_key])
    assert_equal %w[document document], decrypt_for_each(added)
  end

  def test_rotation_preserves_the_envelope_size_by_default
    envelope = SEAL.encrypt(LONG_TEXT, to: ALICE.public_key, padding: { to: 20_000 })
    rotated = SEAL.rotate_dek(envelope, with: ALICE, recipients: [BOB.public_key])
    assert_equal [20_000, LONG_TEXT], [rotated.bytesize, SEAL.decrypt(rotated, with: BOB)]
  end

  def test_rotation_can_grow_capacity_and_slot_size
    rotated = SEAL.rotate_dek(DOCUMENT, with: ALICE, recipients: [BOB.public_key], recipient_capacity: 4,
                                        slot_size: 4096, padding: :none)
    info = SEAL.inspect_envelope(rotated)
    assert_equal [4, 4096], info.to_h.values_at(:recipient_capacity, :slot_size)
  end

  def test_rotation_rejects_a_false_slot_size
    envelope = SEAL.encrypt('payload', to: ALICE.public_key)
    assert_raises(TypeError) do
      SEAL.rotate_dek(envelope, with: ALICE, recipients: [BOB.public_key], slot_size: false)
    end
  end

  def test_rotation_issues_a_new_payload_identity
    rotated = SEAL.rotate_dek(DOCUMENT, with: ALICE, recipients: [ALICE.public_key], padding: :none)
    refute_equal SEAL.inspect_envelope(DOCUMENT).payload_id, SEAL.inspect_envelope(rotated).payload_id
  end

  def test_copied_slot_does_not_open_twice
    header = FORMAT.parse_header(TWO_SLOTS)
    slots_offset = header.raw.bytesize + FORMAT::SECTION_PREFIX_BYTES
    copied = copy_slot(TWO_SLOTS, slots_offset, header.slot_size)
    assert_equal 'ambig', SEAL.decrypt(copied, with: ALICE)
  end

  def test_two_valid_stanzas_for_one_recipient_are_ambiguous
    parsed = internal(:Envelope).parse(TWO_SLOTS)
    section = internal(:RecipientSectionBuilder).new(parsed.section_spec, [ALICE.public_key] * 2,
                                                     parsed.unwrap_dek(ALICE)).call
    crafted = parsed.replace_section(section)
    assert_raises(PQCrypto::Seal::AmbiguousRecipientStanzas) { SEAL.decrypt(crafted, with: ALICE) }
  end
end

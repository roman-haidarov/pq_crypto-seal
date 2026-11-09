# frozen_string_literal: true

require_relative 'test_helper'

class NativeSnapshotTest < Minitest::Test
  include SealTestSupport

  class SnapshotTarget
    include SealTestSupport

    KEY = ('k' * 32).freeze
    NONCE = ('n' * 32).freeze
    LEFT = ('a' * (4 * 1024 * 1024)).freeze
    RIGHT = ('b' * (4 * 1024 * 1024)).freeze
    VARIANTS = [[RIGHT, 'right'], [LEFT, 'left']].freeze

    def initialize
      @input = +LEFT
      @associated_data = +'left'
    end

    def race(rounds, swaps)
      worker = Thread.new { encrypt_rounds(rounds) }
      swaps.times { |index| swap(index) }
      worker.value
    end

    private

    attr_reader :input, :associated_data

    def encrypt_rounds(rounds)
      Array.new(rounds) { encrypt_and_open }
    end

    def encrypt_and_open
      ciphertext, tag = native.aegis256_encrypt(KEY, NONCE, associated_data, input)
      open_with_either(ciphertext, tag)
    end

    def open_with_either(ciphertext, tag)
      native.aegis256_decrypt(KEY, NONCE, 'left', ciphertext, tag)
    rescue PQCrypto::Seal::AuthenticationError
      native.aegis256_decrypt(KEY, NONCE, 'right', ciphertext, tag)
    end

    def swap(index)
      replacement_input, replacement_ad = VARIANTS.fetch(index % 2)
      input.replace(replacement_input)
      associated_data.replace(replacement_ad)
      Thread.pass
    end
  end

  def test_mutating_inputs_during_offloaded_encryption_uses_a_snapshot
    plaintexts = SnapshotTarget.new.race(30, 3_000)
    assert_empty(plaintexts - [SnapshotTarget::LEFT, SnapshotTarget::RIGHT])
  end
end

# frozen_string_literal: true

require_relative 'test_helper'

class IOFileFailureTest < Minitest::Test
  include SealTestSupport

  def test_corrupted_payload_is_not_rebuilt
    FileScenario.run { |files| assert_refused(files, PQCrypto::Seal::AuthenticationError, :rebuild_corrupted) }
  end

  def test_failed_decryption_publishes_nothing
    FileScenario.run { |files| assert_refused(files, PQCrypto::Seal::AuthenticationError, :decrypt_corrupted) }
  end

  def test_resource_limit_publishes_nothing
    FileScenario.run { |files| assert_refused(files, PQCrypto::Seal::ResourceLimitError, :decrypt_limited) }
  end

  def test_inspection_rejects_a_truncated_file
    FileScenario.run { |files| assert_raises(PQCrypto::Seal::FormatError) { files.inspect_truncated } }
  end

  def test_rebuild_rejects_trailing_bytes_and_preserves_the_destination
    in_tmpdir do |directory|
      source = File.join(directory, 'source')
      destination = File.join(directory, 'destination')
      File.binwrite(source, SEAL.encrypt('payload', to: ALICE.public_key) + 'trailing bytes')
      File.binwrite(destination, 'original destination')

      assert_raises(PQCrypto::Seal::FormatError) do
        SEAL.rebuild_recipients_file(source, destination, with: ALICE, recipients: [BOB.public_key])
      end
      assert_equal 'original destination', File.binread(destination)
    end
  end

  private

  def assert_refused(files, error, operation)
    assert_raises(error) { files.public_send(operation) }
    refute_path_exists files.path(FileScenario::DESTINATIONS.fetch(operation))
  end
end

# frozen_string_literal: true

require_relative 'test_helper'

class IOFileTest < Minitest::Test
  include SealTestSupport

  def test_file_round_trip
    FileScenario.run { |files| assert_equal FileScenario::DATA, files.open_as(:sealed, ALICE) }
  end

  def test_rebuilt_file_opens_for_new_recipients
    FileScenario.run { |files| assert_equal FileScenario::DATA, files.open_as(:rebuilt, BOB) }
  end

  def test_added_recipient_opens_the_file
    FileScenario.run { |files| assert_equal FileScenario::DATA, files.open_as(:added, BOB) }
  end

  def test_rotation_preserves_the_file_size
    FileScenario.run { |files| assert_same_size_new_bytes(*files.rotation_pair) }
  end

  def test_rotated_file_satisfies_fixed_padding
    FileScenario.run { |files| assert_equal FileScenario::DATA, files.reopen_rotated_with_fixed_padding }
  end

  def test_rotation_can_grow_capacity
    FileScenario.run { |files| assert_equal 4, files.grown_capacity }
  end

  def test_inspection_reports_the_geometry
    FileScenario.run { |files| assert_equal 4, SEAL.inspect_file(files.sealed).recipient_capacity }
  end

  private

  def assert_same_size_new_bytes(sealed, rotated)
    assert_equal File.size(sealed), File.size(rotated)
    refute_equal File.binread(sealed), File.binread(rotated)
  end
end

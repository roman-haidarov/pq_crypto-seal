# frozen_string_literal: true

require "digest"
require "rubygems/package"
require "rubygems/requirement"

ROOT = File.expand_path("..", __dir__)
SPEC_PATH = File.join(ROOT, "pq_crypto-seal.gemspec")
CHECKSUMS_PATH = File.join(ROOT, "test", "fixtures", "CHECKSUMS.sha256")
EXPECTED_PQ_CRYPTO = Gem::Requirement.new("= 0.6.4")

module ReleaseContract
  module_function

  def check!
    spec = load_spec
    check_dependency!(spec)
    check_wire_sources!
    check_fixture_checksums!
    check_repository_hygiene!
    check_action_pins!
    check_spec_files!(spec)
    check_built_gem!(ARGV.first) if ARGV.first
    puts "release contract: OK"
  end

  def load_spec
    abort "gemspec is missing" unless File.file?(SPEC_PATH)
    Gem::Specification.load(SPEC_PATH) || abort("cannot load gemspec")
  end

  def check_dependency!(spec)
    dependency = spec.runtime_dependencies.find { |item| item.name == "pq_crypto" }
    return if dependency && dependency.requirement == EXPECTED_PQ_CRYPTO

    abort "pq_crypto dependency must be exactly #{EXPECTED_PQ_CRYPTO}"
  end

  def check_wire_sources!
    production_files = Dir[File.join(ROOT, "lib", "**", "*.rb")] +
                       Dir[File.join(ROOT, "ext", "pq_crypto_seal", "*.{c,rb}")]
    production_files.each do |path|
      next unless File.binread(path).include?("CANONICAL_ALGORITHM")

      abort "moving CANONICAL_ALGORITHM alias is forbidden: #{relative(path)}"
    end
  end

  def check_fixture_checksums!
    File.readlines(CHECKSUMS_PATH, chomp: true).reject(&:empty?).each do |line|
      expected, relative_path = line.split(/\s+/, 2)
      path = File.join(ROOT, relative_path)
      abort "fixture is missing: #{relative_path}" unless File.file?(path)

      actual = Digest::SHA256.file(path).hexdigest
      abort "fixture checksum mismatch for #{relative_path}: #{actual}" unless actual == expected
    end
  end

  def check_repository_hygiene!
    forbidden = Dir.glob(File.join(ROOT, "**", ".DS_Store"), File::FNM_DOTMATCH)
    abort "remove .DS_Store before release: #{forbidden.map { |path| relative(path) }.join(', ')}" unless forbidden.empty?
  end

  def check_action_pins!
    workflow = File.join(ROOT, ".github", "workflows", "ci.yml")
    File.readlines(workflow, chomp: true).grep(/^\s*uses:/).each do |line|
      reference = line.split("@", 2).last.to_s.strip
      abort "GitHub Action is not pinned to a commit SHA: #{line.strip}" unless reference.match?(/\A[0-9a-f]{40}\z/)
    end
  end

  def check_spec_files!(spec)
    missing = spec.files.reject { |path| File.file?(File.join(ROOT, path)) }
    abort "gemspec references missing files: #{missing.join(', ')}" unless missing.empty?
  end

  def check_built_gem!(argument)
    gem_path = File.expand_path(argument)
    abort "built gem is missing: #{gem_path}" unless File.file?(gem_path)

    package = Gem::Package.new(gem_path)
    check_dependency!(package.spec)
    check_package_contents!(package.spec.files)
  end

  def check_package_contents!(files)
    forbidden_patterns = [
      %r{\A(?:test|fuzz|script|\.github)/},
      %r{(?:\A|/)\.DS_Store\z},
      %r{/src/raf/},
      %r{/src/aegis128},
      %r{/src/aegis256x(?:2|4)/}
    ]
    forbidden = files.select do |path|
      forbidden_patterns.any? { |pattern| pattern.match?(path) }
    end
    abort "release gem contains forbidden files:\n#{forbidden.join("\n")}" unless forbidden.empty?

    required = [
      "lib/pq_crypto/seal.rb",
      "lib/pq_crypto/seal/core.rb",
      "lib/pq_crypto/seal/envelope.rb",
      "lib/pq_crypto/seal/recipients.rb",
      "lib/pq_crypto/seal/streaming.rb",
      "ext/pq_crypto_seal/extconf.rb",
      "ext/pq_crypto_seal/pq_crypto_seal.c",
      "ext/pq_crypto_seal/vendor/libaegis/src/aegis256/aegis256.c",
      "ext/pq_crypto_seal/vendor/libaegis/src/include/aegis256.h"
    ]
    missing = required - files
    abort "release gem is missing required files: #{missing.join(', ')}" unless missing.empty?
  end

  def relative(path)
    path.delete_prefix(ROOT + File::SEPARATOR)
  end
end

ReleaseContract.check!

# frozen_string_literal: true

require 'digest'
require 'rubygems/package'
require 'rubygems/requirement'

module ReleaseContract
  module Paths
    ROOT = File.expand_path('..', __dir__)
    SPEC = File.join(ROOT, 'pq_crypto-seal.gemspec')
    CHECKSUMS = File.join(ROOT, 'test', 'fixtures', 'CHECKSUMS.sha256')
    WORKFLOW = File.join(ROOT, '.github', 'workflows', 'ci.yml')

    module_function

    def relative(path)
      path.delete_prefix(ROOT + File::SEPARATOR)
    end
  end

  module Rules
    EXPECTED_PQ_CRYPTO = Gem::Requirement.new('~> 0.6')
    REQUIRED_JOBS = %w[test sanitize fuzz release_contract gem-smoke].freeze
    FORBIDDEN_PACKAGE_PATTERNS = [
      %r{\A(?:test|fuzz|script|\.github)/},
      %r{(?:\A|/)\.DS_Store\z},
      %r{/src/raf/},
      %r{/src/aegis128},
      %r{/src/aegis256x(?:2|4)/}
    ].freeze
    REQUIRED_PACKAGE_FILES = %w[
      lib/pq_crypto/seal.rb
      lib/pq_crypto/seal/core.rb
      lib/pq_crypto/seal/envelope.rb
      lib/pq_crypto/seal/format_codecs.rb
      lib/pq_crypto/seal/native.rb
      lib/pq_crypto/seal/options.rb
      lib/pq_crypto/seal/recipients.rb
      lib/pq_crypto/seal/streaming.rb
      ext/pq_crypto_seal/aegis_unused_stubs.c
      ext/pq_crypto_seal/extconf.rb
      ext/pq_crypto_seal/pq_crypto_seal.c
      ext/pq_crypto_seal/pqs_core.c
      ext/pq_crypto_seal/pqs_core.h
      ext/pq_crypto_seal/vendor/libaegis/LICENSE
      ext/pq_crypto_seal/vendor/libaegis/TREE_SHA256
      ext/pq_crypto_seal/vendor/libaegis/src/aegis256/aegis256.c
      ext/pq_crypto_seal/vendor/libaegis/src/common/common.c
      ext/pq_crypto_seal/vendor/libaegis/src/include/aegis.h
      ext/pq_crypto_seal/vendor/libaegis/src/include/aegis256.h
    ].freeze
  end

  module Repository
    module_function

    def check_wire_sources
      production = Dir[File.join(Paths::ROOT, 'lib', '**', '*.rb')] +
                   Dir[File.join(Paths::ROOT, 'ext', 'pq_crypto_seal', '*.{c,h,rb}')]
      offender = production.find { |path| File.binread(path).include?('CANONICAL_ALGORITHM') }
      abort "moving CANONICAL_ALGORITHM alias is forbidden: #{Paths.relative(offender)}" if offender
    end

    def check_fixture_checksums
      File.readlines(Paths::CHECKSUMS, chomp: true).reject(&:empty?).each { |line| check_fixture(line) }
    end

    def check_fixture(line)
      expected, relative_path = line.split(/\s+/, 2)
      path = File.join(Paths::ROOT, relative_path)
      abort "fixture is missing: #{relative_path}" unless File.file?(path)

      actual = Digest::SHA256.file(path).hexdigest
      abort "fixture checksum mismatch for #{relative_path}: #{actual}" unless actual == expected
    end

    def check_hygiene
      forbidden = Dir.glob(File.join(Paths::ROOT, '**', '.DS_Store'), File::FNM_DOTMATCH)
      return if forbidden.empty?

      abort "remove .DS_Store before release: #{forbidden.map { |path| Paths.relative(path) }.join(', ')}"
    end
  end

  module Workflow
    module_function

    def check
      body = read
      check_jobs(body)
      body.each_line.grep(/^\s*(?:-\s+)?uses:/).each { |line| check_pin(line) }
    end

    def read
      abort 'CI workflow is missing' unless File.file?(Paths::WORKFLOW)

      body = File.read(Paths::WORKFLOW)
      return body if body.match?(/permissions:\s*\n\s*contents:\s*read/)

      abort 'CI workflow must set permissions: contents: read'
    end

    def check_jobs(body)
      missing = Rules::REQUIRED_JOBS.reject { |job| body.match?(/^  #{Regexp.escape(job)}:/) }
      abort "CI workflow is missing job #{missing.join(', ')}" unless missing.empty?
    end

    def check_pin(line)
      reference = line.split('@', 2).last.to_s.strip.split(/\s+/, 2).first
      unless reference.to_s.match?(/\A[0-9a-f]{40}\z/)
        abort "GitHub Action is not pinned to a commit SHA: #{line.strip}"
      end
    end
  end

  module Package
    module_function

    def load_spec
      abort 'gemspec is missing' unless File.file?(Paths::SPEC)

      Gem::Specification.load(Paths::SPEC) || abort('cannot load gemspec')
    end

    def check_dependency(spec)
      dependency = spec.runtime_dependencies.find { |item| item.name == 'pq_crypto' }
      requirement = dependency&.requirement
      return if requirement.to_s == Rules::EXPECTED_PQ_CRYPTO.to_s

      abort "pq_crypto dependency must be #{Rules::EXPECTED_PQ_CRYPTO} (got #{requirement.inspect})"
    end

    def check_spec_files(spec)
      missing = spec.files.reject { |path| File.file?(File.join(Paths::ROOT, path)) }
      abort "gemspec references missing files: #{missing.join(', ')}" unless missing.empty?
    end

    def check_built_gem(argument)
      gem_path = File.expand_path(argument)
      abort "built gem is missing: #{gem_path}" unless File.file?(gem_path)

      spec = Gem::Package.new(gem_path).spec
      check_dependency(spec)
      check_contents(spec.files)
    end

    def check_contents(files)
      forbidden = files.grep(Regexp.union(Rules::FORBIDDEN_PACKAGE_PATTERNS))
      abort "release gem contains forbidden files:\n#{forbidden.join("\n")}" unless forbidden.empty?

      missing = Rules::REQUIRED_PACKAGE_FILES - files
      abort "release gem is missing required files: #{missing.join(', ')}" unless missing.empty?
    end
  end

  module_function

  def check(built_gem = nil)
    spec = Package.load_spec
    Package.check_dependency(spec)
    run_repository_checks(spec)
    Package.check_built_gem(built_gem) if built_gem
    puts 'release contract: OK'
  end

  def run_repository_checks(spec)
    Repository.check_wire_sources
    Repository.check_fixture_checksums
    Repository.check_hygiene
    Workflow.check
    Package.check_spec_files(spec)
    Package.check_contents(spec.files)
  end
end

ReleaseContract.check(ARGV.first) if $PROGRAM_NAME == __FILE__

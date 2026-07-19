# frozen_string_literal: true

require_relative "lib/pq_crypto/seal/version"

Gem::Specification.new do |spec|
  spec.name = "pq_crypto-seal"
  spec.version = PQCrypto::Seal::VERSION
  spec.authors = ["Roman Khaidarov"]
  spec.email = ["roman-haidarov@users.noreply.github.com"]

  spec.summary = "Post-quantum envelope encryption for Ruby"
  spec.description = "Versioned multi-recipient document encryption using PQCrypto hybrid KEM, HKDF-SHA256, and vendored AEGIS-256."
  spec.homepage = "https://github.com/roman-haidarov/pq_crypto-seal"
  spec.license = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.7.1")

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir["{lib,ext,test,script,fuzz,.github}/**/*", "pq_crypto-seal.gemspec", "Gemfile", "Rakefile", "README.md", "GET_STARTED.md", "FORMAT.md", "SECURITY.md", "RELEASING.md", "CHANGELOG.md", "LICENSE.txt", "VENDORING.md"]
      .select { |path| File.file?(path) }
      .reject do |path|
        path.match?(/(?:\.o|\.so|\.bundle|\.gem)\z/) ||
          path.end_with?("/Makefile", "/mkmf.log") ||
          path.include?("/.DS_Store") || false
      end
  end
  spec.bindir = "exe"
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/pq_crypto_seal/extconf.rb"]

  spec.add_runtime_dependency "pq_crypto", "~> 0.6.4"
  spec.add_development_dependency "minitest", "~> 5.14"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
end

# frozen_string_literal: true

require "rake/testtask"
require "rake/extensiontask"
require_relative "lib/pq_crypto/seal/version"

Rake::ExtensionTask.new("pq_crypto_seal", Gem::Specification.load("pq_crypto-seal.gemspec")) do |ext|
  ext.lib_dir = "lib/pq_crypto/seal"
end

Rake::TestTask.new do |task|
  task.libs << "lib"
  task.libs << "test"
  task.pattern = "test/**/*_test.rb"
  task.warning = false
end

task test: :compile
task default: :test

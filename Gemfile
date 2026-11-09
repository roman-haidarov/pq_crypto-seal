# frozen_string_literal: true

source 'https://rubygems.org'

gem 'pq_crypto', path: ENV.fetch('PQ_CRYPTO_PATH') if ENV.key?('PQ_CRYPTO_PATH')

gemspec

group :development, :test do
  gem 'minitest', '~> 5.14'
  gem 'rake', '~> 13.0'
  gem 'rake-compiler', '~> 1.2'
end

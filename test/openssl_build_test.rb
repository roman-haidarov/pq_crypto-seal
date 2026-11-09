# frozen_string_literal: true

require 'fileutils'
require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tmpdir'

class OpenSSLBuildTest < Minitest::Test
  EXTCONF = File.expand_path('../ext/pq_crypto_seal/extconf.rb', __dir__)
  NATIVE_TARGET = 'x86_64-linux-gnu'
  NATIVE_CONFIG = "/usr/include/#{NATIVE_TARGET}/openssl/configuration.h"
  NATIVE_CRYPTO = "/usr/lib/#{NATIVE_TARGET}/libcrypto.so.3"

  def setup
    skip 'requires split OpenSSL 3 headers on Linux x86_64' unless
      RUBY_PLATFORM.start_with?('x86_64-linux') && File.file?(NATIVE_CONFIG) && File.file?(NATIVE_CRYPTO)
  end

  def test_multiarch_prefix_follows_mkmf_flags
    Dir.mktmpdir('seal-openssl') do |prefix|
      FileUtils.mkdir_p(["#{prefix}/include/#{NATIVE_TARGET}", "#{prefix}/lib/#{NATIVE_TARGET}"])
      File.symlink('/usr/include/openssl', "#{prefix}/include/openssl")
      File.symlink(File.dirname(NATIVE_CONFIG), "#{prefix}/include/#{NATIVE_TARGET}/openssl")
      File.symlink(NATIVE_CRYPTO, "#{prefix}/lib/#{NATIVE_TARGET}/libcrypto.so.3")
      foreign_headers = "#{prefix}/include/i386-linux-gnu/openssl"
      FileUtils.mkdir_p(foreign_headers)
      File.write("#{foreign_headers}/configuration.h", "#error Wrong architecture\n")
      foreign_libcrypto("#{prefix}/lib/i386-linux-gnu")

      output, status = configure(prefix, { 'OPENSSL_ROOT_DIR' => prefix, 'CFLAGS' => '-m32' }, '--with-cflags=-m64')
      assert status.success?, output
      assert_includes output, "OpenSSL library dir: #{prefix}/lib/#{NATIVE_TARGET}"
      assert_equal NATIVE_CONFIG, File.realpath("#{prefix}/openssl-include/openssl/configuration.h")
    end
  end

  def test_discovery_skips_incompatible_pkg_config_library
    skip 'requires pkg-config' unless system('pkg-config', '--version', out: File::NULL, err: File::NULL)

    Dir.mktmpdir('seal-openssl') do |prefix|
      crypto = foreign_libcrypto(prefix)
      File.write("#{prefix}/openssl.pc", <<~PC)
        Name: OpenSSL
        Description: OpenSSL library for a different target
        Version: 3.0.0
        includedir=/usr/include
        libdir=#{prefix}
      PC

      output, status = configure(prefix, { 'PKG_CONFIG_LIBDIR' => prefix })
      assert status.success?, output
      assert_includes output, "#{crypto}... no"
      assert_includes output, 'OpenSSL source: system prefix'
    end
  end

  private

  def configure(directory, overrides, *arguments)
    env = { 'OPENSSL_ROOT_DIR' => nil, 'OPENSSL_DIR' => nil, 'PKG_CONFIG_PATH' => nil, 'LD_PRELOAD' => nil }
    Open3.capture2e(env.merge(overrides), RbConfig.ruby, EXTCONF, *arguments, chdir: directory)
  end

  def foreign_libcrypto(directory)
    FileUtils.mkdir_p(directory)
    library = File.join(directory, 'libcrypto.so.3')
    FileUtils.cp(NATIVE_CRYPTO, library)
    File.open(library, 'r+b') { |file| file.pwrite([183].pack('v'), 18) }
    library
  end
end

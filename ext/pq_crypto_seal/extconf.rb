# frozen_string_literal: true

require 'fileutils'
require 'mkmf'
require 'pathname'
require 'rbconfig'
require 'shellwords'

module PQCSealBuild
  module BuildHost
    MULTIARCH_TRIPLET = /\A\w+(?:-\w+)*-linux-\w+\z/.freeze

    module_function

    def command_output(*command)
      output = IO.popen(command, err: File::NULL, &:read)
      $?.success? ? output.strip : ''
    rescue StandardError
      ''
    end

    def darwin?
      RbConfig::CONFIG.fetch('host_os', '').match?(/darwin/i)
    end

    def windows?
      RbConfig::CONFIG.fetch('host_os', '').match?(/mswin|mingw|cygwin/i)
    end

    def multiarch
      return @multiarch if defined?(@multiarch)

      @multiarch = compiler_multiarch if RbConfig::CONFIG.fetch('host_os', '').include?('linux')
    end

    def compiler_multiarch
      command = Shellwords.split(cc_command)
      return unless command.pop(2) == ['-c', MakeMakefile::CONFTEST_C]

      triplet = command_output(*command, '-print-multiarch')
      return triplet if triplet.match?(MULTIARCH_TRIPLET)

      target = command_output(*command, '-dumpmachine').sub(/\A([^-]+)-[^-]+-(linux-)/, '\\1-\\2')
      target if target.match?(MULTIARCH_TRIPLET)
    rescue ArgumentError
      nil
    end

    def argument(name)
      flag = "--#{name}"
      inline_argument(flag) || separate_argument(flag)
    end

    def inline_argument(flag)
      found = ARGV.find { |argument| argument.start_with?("#{flag}=") }
      found&.split('=', 2)&.last
    end

    def separate_argument(flag)
      position = ARGV.index(flag)
      position && ARGV[position + 1]
    end
  end

  module OpenSSLInstallation
    LIBRARY_PATTERNS = %w[
      libcrypto.so.3 libcrypto.so.3.* libcrypto.so
      libcrypto.3.dylib libcrypto.3.*.dylib libcrypto.dylib
      libcrypto.a libcrypto.dll.a crypto.lib
    ].freeze
    MAJOR_PATTERN = /^\s*#\s*define\s+OPENSSL_VERSION_MAJOR\s+(\d+)/.freeze
    NUMBER_PATTERN = /^\s*#\s*define\s+OPENSSL_VERSION_NUMBER\s+0x([0-9A-Fa-f]+)L?/.freeze

    module_function

    def library_dirs(prefix)
      triplet = BuildHost.multiarch
      candidates = triplet ? [File.join(prefix, 'lib', triplet)] : []
      candidates.push(File.join(prefix, 'lib64'), File.join(prefix, 'lib'))
      candidates.select { |directory| File.directory?(directory) }.uniq
    end

    def library_file(directory)
      path = library_candidates(directory).find { |candidate| File.file?(candidate) }
      path && File.realpath(path)
    rescue Errno::ENOENT
      nil
    end

    def library_candidates(directory)
      LIBRARY_PATTERNS.flat_map { |pattern| Dir.glob(File.join(directory, pattern)).sort }
    end

    def header_major(include_directory)
      header = File.join(include_directory, 'openssl', 'opensslv.h')
      File.file?(header) ? major_from(File.read(header)) : nil
    rescue StandardError
      nil
    end

    def major_from(contents)
      major = contents[MAJOR_PATTERN, 1]
      return major.to_i if major

      number = contents[NUMBER_PATTERN, 1]
      number && ((number.to_i(16) >> 28) & 0xF)
    end

    def from_dirs(include_directory, library_directory)
      return if include_directory.to_s.empty? || library_directory.to_s.empty?

      include_dir = File.expand_path(include_directory)
      library_dir = File.expand_path(library_directory)
      crypto = header_major(include_dir).to_i >= 3 && library_file(library_dir)
      return unless crypto

      OpenSSLFlags.try_apply(include_directory: include_dir, library_directory: library_dir, crypto_library: crypto)
    end

    def from_prefix(prefix)
      root = prefix.to_s.strip
      return if root.empty?

      expanded = File.expand_path(root)
      first_in(expanded)&.merge(prefix: expanded)
    end

    def first_in(prefix)
      include_directory = File.join(prefix, 'include')
      library_dirs(prefix).lazy.map { |directory| from_dirs(include_directory, directory) }.find(&:itself)
    end
  end

  module OpenSSLDiscovery
    HOMEBREW_PREFIXES = %w[
      /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3
      /opt/homebrew/opt/openssl /usr/local/opt/openssl
    ].freeze
    SYSTEM_PREFIXES = %w[/usr/local /usr].freeze

    module_function

    def call
      explicit_prefix || explicit_dirs || homebrew || pkg_config || system_prefix
    end

    def explicit_prefix
      root = BuildHost.argument('with-openssl-dir') || ENV.fetch('OPENSSL_ROOT_DIR',
                                                                 nil) || ENV.fetch('OPENSSL_DIR', nil)
      return if root.to_s.strip.empty?

      found = OpenSSLInstallation.from_prefix(root) || abort(<<~MSG)
        #{root.inspect} does not point to a complete OpenSSL 3 installation for this compiler target.

        Expected OpenSSL 3 headers below <prefix>/include/openssl and libcrypto
        below <prefix>/lib, <prefix>/lib64, or a Linux multiarch lib directory.
      MSG
      found.merge(source: 'explicit prefix')
    end

    def explicit_dirs
      directories = %w[with-openssl-include with-openssl-lib].map { |name| BuildHost.argument(name) }
      explicit_pair(directories).merge(source: 'explicit include/lib') if directories.any?
    end

    def explicit_pair(directories)
      abort 'Both --with-openssl-include and --with-openssl-lib are required together' unless directories.all?

      OpenSSLInstallation.from_dirs(*directories) ||
        abort('Explicit OpenSSL include/lib paths do not contain a matching OpenSSL 3 headers + libcrypto pair')
    end

    def homebrew
      return unless BuildHost.darwin?

      prefixes = (brew_prefixes + HOMEBREW_PREFIXES).map(&:strip).reject(&:empty?).uniq
      first_prefix(prefixes, 'prefix')
    end

    def brew_prefixes
      return [] unless find_executable('brew')

      %w[openssl@3 openssl].map { |formula| BuildHost.command_output('brew', '--prefix', formula) }
    end

    def pkg_config
      version = pkg_config_version
      return unless version

      directories = %w[includedir libdir].map do |name|
        BuildHost.command_output('pkg-config', "--variable=#{name}", 'openssl')
      end
      OpenSSLInstallation.from_dirs(*directories)&.merge(source: "pkg-config #{version}")
    end

    def pkg_config_version
      return unless find_executable('pkg-config')

      version = BuildHost.command_output('pkg-config', '--modversion', 'openssl')
      version if version.split('.').first.to_i >= 3
    end

    def system_prefix
      first_prefix(SYSTEM_PREFIXES, 'system prefix')
    end

    def first_prefix(prefixes, source)
      found = prefixes.lazy.map { |prefix| OpenSSLInstallation.from_prefix(prefix) }.find(&:itself)
      found&.merge(source: source)
    end
  end

  module IncludeFlags
    SEPARATE_FLAGS = %w[-I -isystem].freeze
    ATTACHED_FLAG = /\A-(?:isystem|I)(.+)\z/.freeze

    module_function

    def paths(flags)
      tokens = Shellwords.split(flags.to_s)
      [nil, *tokens].each_cons(2).filter_map { |previous, token| path_for(previous, token) }
    rescue ArgumentError
      []
    end

    def path_for(previous, token)
      SEPARATE_FLAGS.include?(previous) ? token : token[ATTACHED_FLAG, 1]
    end

    def strip(flags, path)
      flags.to_s.gsub(/(?:\A|\s)-(?:I|isystem)\s*#{Regexp.escape(path)}(?=\s|\z)/, ' ').strip
    end
  end

  module OpenSSLFlags
    REPORT_LABELS = {
      source: 'source', prefix: 'prefix', include_directory: 'include dir',
      library_directory: 'library dir', crypto_library: 'libcrypto'
    }.freeze
    OPENSSL3_PROBE = <<~SRC
      #include <openssl/opensslv.h>
      #if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 3
      #error OpenSSL 3 headers required
      #endif
    SRC
    LINK_PROBE = OPENSSL3_PROBE + <<~SRC
      #include <openssl/evp.h>
      int main(void) {
        EVP_MAC_free(EVP_MAC_fetch(NULL, "HMAC", NULL));
        return 0;
      }
    SRC

    module_function

    def try_apply(installation)
      previous = [$INCFLAGS, $CPPFLAGS, $CFLAGS, $LIBPATH, $LOCAL_LIBS, $LDFLAGS]
      include_directory, library_directory, crypto_library =
        installation.values_at(:include_directory, :library_directory, :crypto_library)
      headers = header_files(include_directory)
      return unless headers.any? { |header| File.basename(header) == 'configuration.h' }

      competing = competing_paths(normalize(include_directory))
      competing.each { |path| strip_everywhere(path) }
      prepend_include(shadow_include(include_directory, headers))
      link(library_directory, crypto_library)
      compatible = checking_for("OpenSSL 3 headers and #{crypto_library}") { try_link(LINK_PROBE) }
      return unless compatible

      pin_dir_config(include_directory, library_directory)
      competing.each { |path| puts "Ignoring competing OpenSSL headers: #{path}" }
      installation
    ensure
      $INCFLAGS, $CPPFLAGS, $CFLAGS, $LIBPATH, $LOCAL_LIBS, $LDFLAGS = previous unless compatible
    end

    def pin_dir_config(include_directory, library_directory)
      $config_dirs['openssl'] = [include_directory, library_directory]
    end

    def competing_paths(selected)
      paths = [$INCFLAGS, $CPPFLAGS, $CFLAGS].flat_map { |flags| IncludeFlags.paths(flags) }.uniq
      paths.select { |path| competing?(path, selected) }
    end

    def competing?(path, selected)
      File.file?(File.join(path, 'openssl', 'opensslv.h')) && normalize(path) != selected
    end

    def strip_everywhere(path)
      $INCFLAGS = IncludeFlags.strip($INCFLAGS, path)
      $CPPFLAGS = IncludeFlags.strip($CPPFLAGS, path)
      $CFLAGS = IncludeFlags.strip($CFLAGS, path)
    end

    def shadow_include(selected_directory, headers)
      return selected_directory if BuildHost.windows?

      shadow = File.expand_path('openssl-include')
      target = File.join(shadow, 'openssl')
      FileUtils.rm_rf(target)
      FileUtils.mkdir_p(target)
      headers.each { |header| File.symlink(header, File.join(target, File.basename(header))) }
      shadow
    rescue SystemCallError, NotImplementedError
      selected_directory
    end

    def header_files(selected_directory)
      directories = [File.join(selected_directory, 'openssl')]
      triplet = BuildHost.multiarch
      directories << File.join(selected_directory, triplet, 'openssl') if triplet
      directories.flat_map { |directory| Dir.glob(File.join(directory, '*.h')).sort }
                 .select { |header| File.file?(header) }.uniq { |header| File.basename(header) }
    end

    def prepend_include(directory)
      flag = "-I#{Shellwords.escape(directory)}"
      $INCFLAGS = "#{flag} #{$INCFLAGS}".strip
      $CPPFLAGS = "#{flag} #{$CPPFLAGS}".strip
    end

    def link(library_directory, crypto_library)
      $LIBPATH = [library_directory] | $LIBPATH
      $LOCAL_LIBS = "#{Shellwords.escape(crypto_library)} #{$LOCAL_LIBS}".strip
      return if BuildHost.windows? || library_directory.start_with?('/usr/lib')

      $LDFLAGS = "-Wl,-rpath,#{Shellwords.escape(library_directory)} #{$LDFLAGS}".strip
    end

    def report(installation)
      REPORT_LABELS.each do |key, label|
        puts "OpenSSL #{label}: #{installation[key]}" if installation.key?(key)
      end
    end

    def normalize(path)
      File.realpath(path)
    rescue Errno::ENOENT
      File.expand_path(path)
    end
  end

  module ExtensionBuild
    HEADERS = %w[
      openssl/evp.h openssl/rand.h openssl/crypto.h openssl/opensslv.h
      openssl/core_names.h openssl/params.h
    ].freeze
    OWN_SOURCES = %w[pq_crypto_seal.c pqs_core.c aegis_unused_stubs.c].freeze
    VENDOR_REQUIRED = %w[aegis256/aegis256.c common/common.c include/aegis.h].freeze
    VENDOR_PATTERNS = %w[aegis256/*.c common/*.c].freeze
    SANITIZER_LIST = /\A[a-z]+(?:,[a-z]+)*\z/.freeze

    module_function

    def configure
      require_files(OWN_SOURCES + %w[pqs_core.h], __dir__)
      configure_sources
      configure_openssl
      require_ruby_api
      configure_compiler
    end

    def configure_openssl
      abort 'A working C compiler and Ruby development headers are required' unless have_devel?

      installation = OpenSSLDiscovery.call
      installation ? OpenSSLFlags.report(installation) : use_default_libcrypto
      require_headers
      check_header_major(installation) if installation
      abort 'OpenSSL 3 libcrypto is required' unless have_func('EVP_MAC_fetch', 'openssl/evp.h')
    end

    def require_headers
      unless checking_for('OpenSSL 3 headers') { try_cpp(OpenSSLFlags::OPENSSL3_PROBE) }
        abort 'OpenSSL 3.0 or newer headers are required'
      end

      HEADERS.each { |header| abort "#{header} is required" unless have_header(header) }
    end

    def use_default_libcrypto
      puts 'OpenSSL 3 prefix: none resolved; using compiler defaults'
      abort 'OpenSSL libcrypto is required' unless have_library('crypto')
    end

    def check_header_major(installation)
      major = OpenSSLInstallation.header_major(installation.fetch(:include_directory)).to_i
      abort 'OpenSSL 3.0 or newer headers are required' if major < 3

      puts "OpenSSL header major: #{major}"
    end

    def require_ruby_api
      abort 'rb_thread_call_without_gvl is required' unless have_func('rb_thread_call_without_gvl', 'ruby/thread.h')

      have_func('rb_nogvl', 'ruby/thread.h')
    end

    def configure_compiler
      $CFLAGS << ' -std=c11 -O3 -Wall -Wextra -fstack-protector-strong'
      sanitizers = sanitizer_list
      return enable_sanitizers(sanitizers) unless sanitizers.empty?

      $CFLAGS << ' -D_FORTIFY_SOURCE=2' unless macro_defined?('_FORTIFY_SOURCE', '#include <stddef.h>')
    end

    def sanitizer_list
      value = ENV.fetch('PQC_SEAL_SANITIZE', '').strip
      value = 'address,undefined' if value == '1'
      return value if value.empty? || value.match?(SANITIZER_LIST)

      abort 'PQC_SEAL_SANITIZE must be 1 or a comma-separated sanitizer list'
    end

    def enable_sanitizers(sanitizers)
      $CFLAGS << " -O1 -g -fno-omit-frame-pointer -fsanitize=#{sanitizers}"
      $LDFLAGS << " -fsanitize=#{sanitizers}"
    end

    def configure_sources
      sources = vendor_sources
      $INCFLAGS << ' -I$(srcdir)/vendor/libaegis/src/include'
      add_source_directories(sources)
      $srcs = OWN_SOURCES + sources.map { |source| File.basename(source) }
    end

    def add_source_directories(sources)
      sources.map { |source| File.dirname(source) }.uniq.each { |directory| add_source_directory(directory) }
    end

    def vendor_sources
      vendor = Pathname(__dir__).join('vendor/libaegis/src')
      abort 'vendored libaegis sources are missing' unless vendor.directory?

      require_files(VENDOR_REQUIRED, vendor)
      VENDOR_PATTERNS.flat_map { |pattern| Dir[vendor.join(pattern).to_s] }.sort
    end

    def require_files(files, directory)
      missing = files.reject { |file| File.file?(File.join(directory, file)) }
      abort "missing native sources under #{directory}: #{missing.join(', ')}" unless missing.empty?
    end

    def add_source_directory(directory)
      relative = Pathname(directory).relative_path_from(Pathname(__dir__))
      $VPATH << "$(srcdir)/#{relative}"
      $INCFLAGS << " -I$(srcdir)/#{relative}"
    end
  end
end

PQCSealBuild::ExtensionBuild.configure
create_makefile('pq_crypto/seal/pq_crypto_seal')

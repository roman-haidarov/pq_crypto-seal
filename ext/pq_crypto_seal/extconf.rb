# frozen_string_literal: true

require "mkmf"
require "pathname"
require "rbconfig"
require "shellwords"

extension_name = "pq_crypto/seal/pq_crypto_seal"

# Ruby 2.7 installations on macOS are often built against Homebrew OpenSSL 1.1.
# Their RbConfig can inject that old prefix into every extension build, even when
# OpenSSL 3 is installed separately. Select one complete OpenSSL 3 installation,
# remove competing OpenSSL header paths, and link the selected libcrypto by its
# absolute path so headers and library cannot silently come from different roots.

def command_output(*command)
  IO.popen(command, err: File::NULL, &:read).to_s.strip
rescue StandardError
  ""
end

def host_os
  RbConfig::CONFIG.fetch("host_os", "")
end

def windows_host?
  host_os =~ /mswin|mingw|cygwin/i
end

def openssl_library_dirs(prefix)
  dirs = Dir.glob(File.join(prefix, "lib", "*-linux-gnu"))
  dirs.concat([File.join(prefix, "lib64"), File.join(prefix, "lib")])
  dirs.select { |directory| File.directory?(directory) }.uniq
end

def openssl_library_file(directory)
  candidates = [
    File.join(directory, "libcrypto.so.3"),
    *Dir.glob(File.join(directory, "libcrypto.so.3.*")).sort,
    File.join(directory, "libcrypto.so"),
    File.join(directory, "libcrypto.3.dylib"),
    *Dir.glob(File.join(directory, "libcrypto.3.*.dylib")).sort,
    File.join(directory, "libcrypto.dylib"),
    File.join(directory, "libcrypto.a"),
    File.join(directory, "libcrypto.dll.a"),
    File.join(directory, "crypto.lib")
  ]

  path = candidates.find { |candidate| File.file?(candidate) }
  path && File.realpath(path)
rescue Errno::ENOENT
  nil
end

def openssl_header_major(include_directory)
  header = File.join(include_directory, "openssl", "opensslv.h")
  return nil unless File.file?(header)

  contents = File.read(header)
  major = contents[/^\s*#\s*define\s+OPENSSL_VERSION_MAJOR\s+(\d+)/, 1]
  return major.to_i if major

  # OpenSSL 1.x has no OPENSSL_VERSION_MAJOR. Parse the high hexadecimal nibble
  # only to reject it cleanly; OpenSSL 3 installations always define the major.
  number = contents[/^\s*#\s*define\s+OPENSSL_VERSION_NUMBER\s+0x([0-9A-Fa-f]+)L?/, 1]
  number ? (number.to_i(16) >> 28) & 0xF : nil
rescue StandardError
  nil
end

def openssl_installation(include_directory, library_directory)
  return nil unless include_directory && library_directory

  include_directory = File.expand_path(include_directory)
  library_directory = File.expand_path(library_directory)
  return nil unless openssl_header_major(include_directory).to_i >= 3

  crypto_library = openssl_library_file(library_directory)
  return nil unless crypto_library

  {
    include_directory: include_directory,
    library_directory: library_directory,
    crypto_library: crypto_library
  }
end

def openssl_prefix_installation(prefix)
  return nil if prefix.nil? || prefix.to_s.strip.empty?

  prefix = File.expand_path(prefix.to_s.strip)
  include_directory = File.join(prefix, "include")
  openssl_library_dirs(prefix).each do |library_directory|
    installation = openssl_installation(include_directory, library_directory)
    return installation.merge(prefix: prefix) if installation
  end
  nil
end

def argument_value(name)
  prefix = "--#{name}"
  ARGV.each_with_index do |argument, index|
    return argument.split("=", 2)[1] if argument.start_with?("#{prefix}=")
    return ARGV[index + 1] if argument == prefix && ARGV[index + 1]
  end
  nil
end

def explicit_openssl_installation
  explicit_root = argument_value("with-openssl-dir") || ENV["OPENSSL_ROOT_DIR"] || ENV["OPENSSL_DIR"]
  if explicit_root && !explicit_root.to_s.strip.empty?
    installation = openssl_prefix_installation(explicit_root)
    abort <<~MSG unless installation
      #{explicit_root.inspect} does not point to a complete OpenSSL 3 installation.

      Expected OpenSSL 3 headers below <prefix>/include/openssl and libcrypto
      below <prefix>/lib, <prefix>/lib64, or a Linux multiarch lib directory.
    MSG
    return installation.merge(source: "explicit prefix")
  end

  explicit_include = argument_value("with-openssl-include")
  explicit_library = argument_value("with-openssl-lib")
  return nil unless explicit_include || explicit_library

  abort "Both --with-openssl-include and --with-openssl-lib are required together" unless explicit_include && explicit_library
  installation = openssl_installation(explicit_include, explicit_library)
  abort "Explicit OpenSSL include/lib paths do not contain a matching OpenSSL 3 headers + libcrypto pair" unless installation

  installation.merge(source: "explicit include/lib")
end

def pkg_config_openssl_installation
  return nil unless find_executable("pkg-config")

  version = command_output("pkg-config", "--modversion", "openssl")
  return nil if version.empty? || version.split(".").first.to_i < 3

  include_directory = command_output("pkg-config", "--variable=includedir", "openssl")
  library_directory = command_output("pkg-config", "--variable=libdir", "openssl")
  installation = openssl_installation(include_directory, library_directory)
  installation && installation.merge(source: "pkg-config #{version}")
end

def discover_openssl3_installation
  explicit = explicit_openssl_installation
  return explicit if explicit

  candidates = []
  if host_os =~ /darwin/i && find_executable("brew")
    candidates << command_output("brew", "--prefix", "openssl@3")
    candidates << command_output("brew", "--prefix", "openssl")
  end
  candidates.concat(
    %w[
      /opt/homebrew/opt/openssl@3
      /usr/local/opt/openssl@3
      /opt/homebrew/opt/openssl
      /usr/local/opt/openssl
    ]
  ) if host_os =~ /darwin/i

  candidates.compact.map(&:strip).reject(&:empty?).uniq.each do |prefix|
    installation = openssl_prefix_installation(prefix)
    return installation.merge(source: "prefix", prefix: File.expand_path(prefix)) if installation
  end

  pkg_config_openssl_installation ||
    openssl_prefix_installation("/usr/local")&.merge(source: "system prefix", prefix: "/usr/local") ||
    openssl_prefix_installation("/usr")&.merge(source: "system prefix", prefix: "/usr")
end

def normalize_existing_path(path)
  File.realpath(path)
rescue Errno::ENOENT
  File.expand_path(path)
end

def include_paths_from_flags(flags)
  tokens = Shellwords.split(flags.to_s)
  paths = []
  index = 0

  while index < tokens.length
    token = tokens[index]
    case token
    when "-I", "-isystem"
      paths << tokens[index + 1] if tokens[index + 1]
      index += 2
      next
    when /\A-I(.+)\z/
      paths << Regexp.last_match(1)
    when /\A-isystem(.+)\z/
      paths << Regexp.last_match(1)
    end
    index += 1
  end

  paths
rescue ArgumentError
  []
end

def strip_include_path(flags, path)
  escaped = Regexp.escape(path)
  flags.to_s
       .gsub(/(?:\A|\s)-I\s*#{escaped}(?=\s|\z)/, " ")
       .gsub(/(?:\A|\s)-isystem\s*#{escaped}(?=\s|\z)/, " ")
       .strip
end

def remove_competing_openssl_headers!(selected_include_directory)
  selected = normalize_existing_path(selected_include_directory)
  competing = [$INCFLAGS, $CPPFLAGS, $CFLAGS]
              .flat_map { |flags| include_paths_from_flags(flags) }
              .uniq
              .select do |path|
    File.file?(File.join(path, "openssl", "opensslv.h")) && normalize_existing_path(path) != selected
  end

  competing.each do |path|
    $INCFLAGS = strip_include_path($INCFLAGS, path)
    $CPPFLAGS = strip_include_path($CPPFLAGS, path)
    $CFLAGS = strip_include_path($CFLAGS, path)
    puts "Ignoring competing OpenSSL headers: #{path}"
  end
end

def configure_selected_openssl!(installation)
  include_directory = installation.fetch(:include_directory)
  library_directory = installation.fetch(:library_directory)
  crypto_library = installation.fetch(:crypto_library)

  remove_competing_openssl_headers!(include_directory)

  # Do not call dir_config("openssl") here. On Ruby 2.7 it can reuse the
  # --with-openssl-dir value from Ruby's own build and reintroduce OpenSSL 1.1.
  $INCFLAGS = "-I#{Shellwords.escape(include_directory)} #{$INCFLAGS}".strip
  $CPPFLAGS = "-I#{Shellwords.escape(include_directory)} #{$CPPFLAGS}".strip
  $LIBPATH.unshift(library_directory) unless $LIBPATH.include?(library_directory)
  $LOCAL_LIBS = "#{Shellwords.escape(crypto_library)} #{$LOCAL_LIBS}".strip

  unless windows_host? || library_directory.start_with?("/usr/lib")
    $LDFLAGS = "-Wl,-rpath,#{Shellwords.escape(library_directory)} #{$LDFLAGS}".strip
  end

  puts "OpenSSL source: #{installation.fetch(:source)}"
  puts "OpenSSL prefix: #{installation[:prefix]}" if installation[:prefix]
  puts "OpenSSL include dir: #{include_directory}"
  puts "OpenSSL library dir: #{library_directory}"
  puts "OpenSSL libcrypto: #{crypto_library}"
end

selected_openssl = discover_openssl3_installation
if selected_openssl
  configure_selected_openssl!(selected_openssl)
else
  puts "OpenSSL 3 prefix: none resolved; using compiler defaults"
  abort "OpenSSL libcrypto is required" unless have_library("crypto")
end

%w[openssl/evp.h openssl/hmac.h openssl/rand.h openssl/crypto.h openssl/opensslv.h].each do |header|
  abort "#{header} is required" unless have_header(header)
end

if selected_openssl
  header_major = openssl_header_major(selected_openssl.fetch(:include_directory))
  abort "OpenSSL 3.0 or newer headers are required" unless header_major && header_major >= 3
  puts "OpenSSL header major: #{header_major}"
end

abort "rb_thread_call_without_gvl is required" unless have_func("rb_thread_call_without_gvl", "ruby/thread.h")

$CFLAGS << " -std=c11 -O3 -Wall -Wextra"
if ENV["PQC_SEAL_SANITIZE"] == "1"
  $CFLAGS << " -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
  $LDFLAGS << " -fsanitize=address,undefined"
end

vendor = Pathname(__dir__).join("vendor/libaegis/src")
patterns = %w[
  aegis256/*.c common/*.c
]
sources = patterns.flat_map { |pattern| Dir[vendor.join(pattern).to_s] }.sort
abort "vendored libaegis sources are missing" if sources.empty?

$INCFLAGS << " -I$(srcdir)/vendor/libaegis/src/include"
source_dirs = sources.map { |source| File.dirname(source) }.uniq
source_dirs.each do |directory|
  relative = Pathname(directory).relative_path_from(Pathname(__dir__))
  $VPATH << "$(srcdir)/#{relative}"
  $INCFLAGS << " -I$(srcdir)/#{relative}"
end
$srcs = ["pq_crypto_seal.c", "aegis_unused_stubs.c"] + sources.map { |source| File.basename(source) }

create_makefile(extension_name)

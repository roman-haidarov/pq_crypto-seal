#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "net/http"
require "tmpdir"
require "uri"

ROOT = File.expand_path("..", __dir__)
VENDOR = File.join(ROOT, "ext/pq_crypto_seal/vendor/libaegis")
VERSION = "0.10.3"
URL = "https://github.com/aegis-aead/libaegis/archive/refs/tags/#{VERSION}.tar.gz"
ARCHIVE_SHA256 = "2f2682c1d08d9a5510caca1c82e3f8ea91f7085fef2ecbed0c398b2a921c79b1"
TREE_SHA256_FILE = File.join(VENDOR, "TREE_SHA256")

def download(uri, limit = 5)
  abort "too many redirects while downloading libaegis" if limit <= 0
  response = Net::HTTP.get_response(uri)
  case response
  when Net::HTTPSuccess
    response.body
  when Net::HTTPRedirection
    location = response["location"]
    abort "download redirect without Location" unless location
    download(URI.join(uri.to_s, location), limit - 1)
  else
    abort "download failed: HTTP #{response.code}"
  end
end

def tree_sha256(directory)
  digest = Digest::SHA256.new
  Dir.chdir(directory) do
    Dir.glob("**/*", File::FNM_DOTMATCH).sort.each do |path|
      next if path == "." || path == ".." || path == "TREE_SHA256"
      next unless File.file?(path)
      bytes = File.binread(path)
      digest << [path.bytesize].pack("N") << path.b
      digest << [bytes.bytesize].pack("Q>") << bytes
    end
  end
  digest.hexdigest
end

def verify!
  expected = File.read(TREE_SHA256_FILE).strip
  actual = tree_sha256(VENDOR)
  abort "libaegis vendor tree mismatch\nexpected: #{expected}\nactual:   #{actual}" unless actual == expected
  puts "libaegis #{VERSION} vendor tree verified: #{actual}"
end

def update!
  Dir.mktmpdir("libaegis") do |tmp|
    archive = File.join(tmp, "libaegis.tar.gz")
    uri = URI(URL)
    File.binwrite(archive, download(uri))
    actual = Digest::SHA256.file(archive).hexdigest
    abort "archive checksum mismatch: #{actual}" unless actual == ARCHIVE_SHA256
    abort "tar extraction failed" unless system("tar", "-xzf", archive, "-C", tmp)
    extracted = Dir[File.join(tmp, "libaegis-*")].find { |path| File.directory?(path) }
    abort "extracted libaegis directory not found" unless extracted
    FileUtils.rm_rf(VENDOR)
    FileUtils.mkdir_p(VENDOR)
    FileUtils.cp_r(File.join(extracted, "src"), VENDOR)
    FileUtils.cp(File.join(extracted, "LICENSE"), VENDOR)
    File.write(TREE_SHA256_FILE, tree_sha256(VENDOR) + "\n")
  end
  verify!
end

case ARGV.first
when nil, "--check"
  verify!
when "--update"
  update!
else
  abort "usage: #{$PROGRAM_NAME} [--check|--update]"
end

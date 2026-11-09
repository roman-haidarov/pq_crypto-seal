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
TREE_SHA256 = "fddf2ab4de0c6ff783face9f957c395a5b1a27e96630ec0e795d50d5c03ec28e"

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

def verify!(directory = VENDOR)
  checksum_file = File.join(directory, "TREE_SHA256")
  abort "missing vendored libaegis checksum: #{checksum_file}" unless File.file?(checksum_file)
  abort "vendored libaegis checksum file does not match the pinned source tree" unless File.read(checksum_file).strip == TREE_SHA256

  actual = tree_sha256(directory)
  abort "libaegis vendor tree mismatch\nexpected: #{TREE_SHA256}\nactual:   #{actual}" unless actual == TREE_SHA256
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
    snapshot = File.join(tmp, "snapshot")
    FileUtils.mkdir_p(snapshot)
    FileUtils.cp_r(File.join(extracted, "src"), snapshot)
    FileUtils.cp(File.join(extracted, "LICENSE"), snapshot)
    File.write(File.join(snapshot, "TREE_SHA256"), TREE_SHA256 + "\n")
    verify!(snapshot)
    FileUtils.rm_rf(VENDOR)
    FileUtils.mkdir_p(File.dirname(VENDOR))
    FileUtils.mv(snapshot, VENDOR)
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

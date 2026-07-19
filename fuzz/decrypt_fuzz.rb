# frozen_string_literal: true

# Decrypt/parse fuzzer for pq_crypto-seal.
#
# Two modes:
#   * AFL harness  : reads one input from stdin (when AFL is available).
#   * CI self-fuzz : `--ci --iterations N` generates valid envelopes and feeds
#                    random mutations of them, plus fully random inputs, through
#                    the public decrypt path. Any exception other than the
#                    documented, expected error classes fails the run.

require "pq_crypto/seal"
require "stringio"

EXPECTED = [
  PQCrypto::Seal::Error,
  PQCrypto::Error,
  ArgumentError,
  EOFError,
  RangeError
].freeze

KEYPAIR = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
STRANGER = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)

def decrypt_attempt(input, keypair)
  PQCrypto::Seal.decrypt(input.b, with: keypair)
rescue *EXPECTED
  nil
end

def strict_decrypt(input, keypair)
  PQCrypto::Seal.decrypt(input.b, with: keypair)
  :opened
rescue *EXPECTED
  :rejected
rescue StandardError, SystemStackError => e
  warn "UNEXPECTED #{e.class}: #{e.message}"
  warn e.backtrace.first(8).join("\n")
  raise
end

def sample_valid_envelope
  data = Random.bytes(rand(0..4096))
  meta = Random.bytes(rand(0..64))
  PQCrypto::Seal.encrypt(
    data, to: KEYPAIR.public_key, metadata: meta,
    padding: [:none, :padme].sample
  )
end

def mutate(bytes)
  copy = bytes.dup
  return copy if copy.empty?

  case rand(6)
  when 0 # flip bits
    rand(1..8).times { copy.setbyte(rand(copy.bytesize), rand(256)) }
  when 1 # truncate
    copy = copy.byteslice(0, rand(0...copy.bytesize)).to_s.b
  when 2 # extend with junk
    copy << Random.bytes(rand(1..64))
  when 3 # zero a run
    start = rand(copy.bytesize)
    len = rand(1..[32, copy.bytesize - start].min)
    len.times { |i| copy.setbyte(start + i, 0) }
  when 4 # duplicate a slice
    start = rand(copy.bytesize)
    len = rand(1..[64, copy.bytesize - start].min)
    copy << copy.byteslice(start, len)
  else # single-byte increment
    i = rand(copy.bytesize)
    copy.setbyte(i, (copy.getbyte(i) + 1) & 0xff)
  end
  copy.b
end

def run_ci(iterations)
  opened = 0
  rejected = 0
  base = sample_valid_envelope

  iterations.times do |i|
    base = sample_valid_envelope if (i % 500).zero?

    candidate =
      case rand(3)
      when 0 then Random.bytes(rand(0..4096)) # fully random
      when 1 then mutate(base)                # mutated valid envelope
      else        base.dup                    # unmodified (sanity)
      end

    result = strict_decrypt(candidate, KEYPAIR)
    strict_decrypt(candidate, STRANGER)

    result == :opened ? opened += 1 : rejected += 1
  end

  raise "fuzzer never opened a valid envelope" if opened.zero?

  puts "fuzz complete: #{iterations} iterations, #{opened} opened, #{rejected} rejected"
end

if ARGV.include?("--ci")
  idx = ARGV.index("--iterations")
  iterations = idx ? Integer(ARGV[idx + 1]) : 10_000
  run_ci(iterations)
elsif defined?(AFL)
  AFL.loop { decrypt_attempt($stdin.read, KEYPAIR) }
else
  decrypt_attempt($stdin.read, KEYPAIR)
end

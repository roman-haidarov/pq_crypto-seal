# frozen_string_literal: true

require 'English'
require 'pq_crypto/seal'
require 'stringio'

module DecryptFuzz
  EXPECTED = [
    PQCrypto::Seal::FormatError,
    PQCrypto::Seal::AuthenticationError,
    PQCrypto::Seal::UnsupportedSuiteError,
    PQCrypto::Seal::RecipientNotFoundError,
    PQCrypto::Seal::AmbiguousRecipientStanzas,
    PQCrypto::Seal::InvalidConfigurationError,
    PQCrypto::Seal::ResourceLimitError,
    PQCrypto::Seal::RecipientCapacityExceeded,
    PQCrypto::Error,
    ArgumentError,
    EOFError,
    RangeError
  ].freeze
  KEYPAIR = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
  STRANGER = PQCrypto::HybridKEM.generate(PQCrypto::Seal::WRAP_KEM_ALGORITHM)
  MUTATIONS = %i[scramble truncate append zero_run repeat_run increment].freeze

  class Campaign
    def initialize(iterations)
      @iterations = iterations
      @tally = Hash.new(0)
      @base = DecryptFuzz.sample_envelope
    end

    def call
      iterations.times { |index| step(index) }
      opened = tally[:opened]
      raise 'fuzzer never opened a valid envelope' if opened.zero?

      puts "fuzz complete: #{iterations} iterations, #{opened} opened, #{tally[:rejected]} rejected"
    end

    private

    attr_reader :iterations, :tally

    def step(index)
      @base = DecryptFuzz.sample_envelope if (index % 500).zero?
      candidate = DecryptFuzz.candidate(@base)
      DecryptFuzz.strict(candidate, STRANGER)
      tally[DecryptFuzz.strict(candidate, KEYPAIR)] += 1
    end
  end

  module_function

  def main(argv)
    return Campaign.new(iterations(argv)).call if argv.include?('--ci')

    defined?(AFL) ? AFL.loop { attempt_stdin } : attempt_stdin
  end

  def attempt_stdin
    attempt($stdin.read, KEYPAIR)
  end

  def iterations(argv)
    position = argv.index('--iterations')
    position ? Integer(argv[position + 1]) : 10_000
  end

  def attempt(input, keypair)
    PQCrypto::Seal.decrypt(input.b, with: keypair)
  rescue *EXPECTED
    nil
  end

  def strict(input, keypair)
    PQCrypto::Seal.decrypt(input.b, with: keypair)
    :opened
  rescue *EXPECTED
    :rejected
  rescue StandardError, SystemStackError
    report_unexpected($ERROR_INFO)
    raise
  end

  def report_unexpected(error)
    warn "UNEXPECTED #{error.class}: #{error.message}"
    warn error.backtrace.first(8).join("\n")
  end

  def sample_envelope
    PQCrypto::Seal.encrypt(
      Random.bytes(rand(0..4096)), to: KEYPAIR.public_key,
                                   metadata: Random.bytes(rand(0..64)), padding: %i[none padme].sample
    )
  end

  def candidate(base)
    case rand(3)
    when 0 then Random.bytes(rand(0..4096))
    when 1 then mutate(base)
    else base.dup
    end
  end

  def mutate(bytes)
    copy = bytes.dup
    return copy if copy.empty?

    public_send(MUTATIONS.sample, copy).b
  end

  def scramble(copy)
    rand(1..8).times { copy.setbyte(rand(copy.bytesize), rand(256)) }
    copy
  end

  def truncate(copy)
    copy.byteslice(0, rand(0...copy.bytesize)).to_s
  end

  def append(copy)
    copy << Random.bytes(rand(1..64))
  end

  def zero_run(copy)
    size = copy.bytesize
    start = rand(size)
    rand(1..[32, size - start].min).times { |offset| copy.setbyte(start + offset, 0) }
    copy
  end

  def repeat_run(copy)
    size = copy.bytesize
    start = rand(size)
    copy << copy.byteslice(start, rand(1..[64, size - start].min))
  end

  def increment(copy)
    index = rand(copy.bytesize)
    copy.setbyte(index, (copy.getbyte(index) + 1) & 0xff)
    copy
  end
end

DecryptFuzz.main(ARGV) if $PROGRAM_NAME == __FILE__

# frozen_string_literal: true

module PQCrypto
  module Seal
    module Binary
      INTEGER_TYPES = {
        u8: [1, 'C', 0xff],
        u16: [2, 'n', 0xffff],
        u32: [4, 'N', 0xffff_ffff],
        u64: [8, 'Q>', 0xffff_ffff_ffff_ffff]
      }.freeze

      class Reader
        attr_reader :offset

        def initialize(bytes, offset = 0)
          @bytes = String(bytes)
          @offset = Integer(offset)
        end

        INTEGER_TYPES.each do |name, (length, directive, _max)|
          define_method(name) { bytes(length).unpack1(directive) }
        end

        def bytes(length)
          count = Integer(length)
          Binary.check_available(@bytes, offset, count)
          value = @bytes.unpack1("@#{offset}a#{count}")
          @offset += count
          value
        end

        def remaining
          @bytes.bytesize - offset
        end

        def finished?
          remaining.zero?
        end
      end

      class << self
        INTEGER_TYPES.each do |name, (_length, directive, max)|
          define_method(name) { |value| [integer(value, max)].pack(directive) }
        end

        def check_available(bytes, offset, length)
          raise FormatError, 'invalid offset' if offset.negative? || length.negative?

          available = bytes.bytesize - offset
          raise FormatError, 'truncated envelope' if available.negative? || length > available
        end

        def view(string)
          string.encoding == Encoding::BINARY ? string : string.b
        end

        def integer(value, max)
          number = Integer(value)
          raise RangeError, 'integer is out of range' unless number.between?(0, max)

          number
        end
      end
    end
  end
end

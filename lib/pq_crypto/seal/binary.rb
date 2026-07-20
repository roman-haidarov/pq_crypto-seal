# frozen_string_literal: true

module PQCrypto
  module Seal
    module Binary
      INTEGER_TYPES = {
        u8: [1, "C", 0xff],
        u16: [2, "n", 0xffff],
        u32: [4, "N", 0xffff_ffff],
        u64: [8, "Q>", 0xffff_ffff_ffff_ffff]
      }.freeze

      class Reader
        attr_reader :offset

        def initialize(bytes, offset = 0)
          @bytes = String(bytes).b
          @offset = Integer(offset)
        end

        INTEGER_TYPES.each do |name, (length, directive, _max)|
          define_method(name) { bytes(length).unpack1(directive) }
        end

        def bytes(length)
          length = Integer(length)
          Binary.ensure_available!(@bytes, offset, length)
          value = @bytes.byteslice(offset, length).b
          @offset += length
          value
        end

        def finished?
          offset == @bytes.bytesize
        end
      end

      class << self
        INTEGER_TYPES.each do |name, (_length, directive, max)|
          define_method(name) { |value| [integer!(value, max)].pack(directive) }
          define_method("read_#{name}") { |bytes, offset| read_with(bytes, offset, &name) }
        end

        def read_bytes(bytes, offset, length)
          read_with(bytes, offset) { |reader| reader.bytes(length) }
        end

        def ensure_available!(bytes, offset, length)
          offset, length = Integer(offset), Integer(length)

          raise FormatError, "invalid offset" if offset.negative? || length.negative?
          raise FormatError, "truncated envelope" if offset > bytes.bytesize || length > bytes.bytesize - offset
        end

        def integer!(value, max)
          number = Integer(value)
          raise RangeError, "integer is out of range" if number.negative? || number > max

          number
        end

        private

        def read_with(bytes, offset)
          reader = Reader.new(bytes, offset)
          [yield(reader), reader.offset]
        end
      end
    end
  end
end

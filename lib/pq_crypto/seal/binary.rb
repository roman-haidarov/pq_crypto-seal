# frozen_string_literal: true

module PQCrypto
  module Seal
    module Binary
      module_function

      def u8(value)
        [integer!(value, 0xff)].pack("C")
      end

      def u16(value)
        [integer!(value, 0xffff)].pack("n")
      end

      def u32(value)
        [integer!(value, 0xffff_ffff)].pack("N")
      end

      def u64(value)
        [integer!(value, 0xffff_ffff_ffff_ffff)].pack("Q>")
      end

      def read_u8(bytes, offset)
        ensure_available!(bytes, offset, 1)
        [bytes.getbyte(offset), offset + 1]
      end

      def read_u16(bytes, offset)
        ensure_available!(bytes, offset, 2)
        [bytes.byteslice(offset, 2).unpack1("n"), offset + 2]
      end

      def read_u32(bytes, offset)
        ensure_available!(bytes, offset, 4)
        [bytes.byteslice(offset, 4).unpack1("N"), offset + 4]
      end

      def read_u64(bytes, offset)
        ensure_available!(bytes, offset, 8)
        [bytes.byteslice(offset, 8).unpack1("Q>"), offset + 8]
      end

      def read_bytes(bytes, offset, length)
        raise FormatError, "negative length" if length.negative?
        ensure_available!(bytes, offset, length)
        [bytes.byteslice(offset, length).b, offset + length]
      end

      def ensure_available!(bytes, offset, length)
        raise FormatError, "invalid offset" if offset.negative? || length.negative?
        raise FormatError, "truncated envelope" if offset > bytes.bytesize || length > bytes.bytesize - offset
      end

      def integer!(value, max)
        number = Integer(value)
        raise RangeError, "integer is out of range" if number.negative? || number > max
        number
      end
    end
  end
end

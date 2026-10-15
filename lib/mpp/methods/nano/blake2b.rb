# typed: true
# frozen_string_literal: true

module Mpp
  module Methods
    module Nano
      # Minimal unkeyed BLAKE2b (RFC 7693) with a variable digest length.
      #
      # Nano address checksums use a 5-byte BLAKE2b digest, which is not a
      # truncation of BLAKE2b-512 and is not exposed by Ruby's OpenSSL
      # bindings, so it is computed here instead of adding a dependency.
      module Blake2b
        extend T::Sig

        MASK = 0xFFFFFFFFFFFFFFFF
        BLOCK_SIZE = 128

        IV = [
          0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        ].freeze

        SIGMA = [
          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
          [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
          [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
          [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
          [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
          [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
          [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
          [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
          [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
          [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
        ].freeze

        # State words mixed by each G call: four columns, then four diagonals.
        MIX_LANES = [
          [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
          [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]
        ].freeze

        module_function

        # Returns the BLAKE2b digest of `data` as a binary string of `size` bytes.
        sig { params(data: String, size: Integer).returns(String) }
        def digest(data, size = 64)
          Kernel.raise ArgumentError, "digest size must be between 1 and 64" unless size.between?(1, 64)

          bytes = data.b
          h = IV.dup
          h[0] ^= 0x01010000 ^ size

          offset = 0
          total = bytes.bytesize
          # Every block but the last is compressed as-is; the last (possibly
          # empty or partial) block is zero-padded and flagged as final.
          while total - offset > BLOCK_SIZE
            compress(h, T.must(bytes.byteslice(offset, BLOCK_SIZE)), offset + BLOCK_SIZE, false)
            offset += BLOCK_SIZE
          end
          last = T.must(bytes.byteslice(offset, BLOCK_SIZE)).ljust(BLOCK_SIZE, "\0")
          compress(h, last, total, true)

          T.must(h.pack("Q<8").byteslice(0, size))
        end

        sig { params(h: T::Array[Integer], block: String, counter: Integer, final: T::Boolean).void }
        def compress(h, block, counter, final)
          m = T.cast(block.unpack("Q<16"), T::Array[Integer])
          v = h + IV
          v[12] = T.must(v[12]) ^ (counter & MASK)
          v[13] = T.must(v[13]) ^ (counter >> 64)
          v[14] = T.must(v[14]) ^ MASK if final

          12.times do |round|
            s = SIGMA.fetch(round % 10)
            MIX_LANES.each_with_index do |lanes, i|
              mix(v, lanes, m.fetch(s.fetch(2 * i)), m.fetch(s.fetch((2 * i) + 1)))
            end
          end

          8.times { |i| h[i] = T.must(h[i]) ^ T.must(v[i]) ^ T.must(v[i + 8]) }
        end

        sig { params(v: T::Array[Integer], lanes: T::Array[Integer], x: Integer, y: Integer).void }
        def mix(v, lanes, x, y)
          a, b, c, d = lanes.fetch(0), lanes.fetch(1), lanes.fetch(2), lanes.fetch(3)
          va = T.must(v[a])
          vb = T.must(v[b])
          vc = T.must(v[c])
          vd = T.must(v[d])

          va = (va + vb + x) & MASK
          vd = rotr(vd ^ va, 32)
          vc = (vc + vd) & MASK
          vb = rotr(vb ^ vc, 24)
          va = (va + vb + y) & MASK
          vd = rotr(vd ^ va, 16)
          vc = (vc + vd) & MASK
          vb = rotr(vb ^ vc, 63)

          v[a] = va
          v[b] = vb
          v[c] = vc
          v[d] = vd
        end

        sig { params(value: Integer, bits: Integer).returns(Integer) }
        def rotr(value, bits)
          ((value >> bits) | (value << (64 - bits))) & MASK
        end

        private_class_method :compress, :mix, :rotr
      end
    end
  end
end

# typed: true
# frozen_string_literal: true

module Mpp
  module Methods
    module Nano
      # Nano account addresses (`nano_` and legacy `xrb_`).
      #
      # An address is the 256-bit public key followed by a 40-bit BLAKE2b
      # checksum, both in Nano's base32 alphabet. Accounts are compared by
      # public key, so `nano_` and `xrb_` forms of one key are equal.
      module Address
        extend T::Sig

        ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"
        PATTERN = /\A(?:nano|xrb)_[13][13456789abcdefghijkmnopqrstuwxyz]{59}\z/
        PUBLIC_KEY_PATTERN = /\A\h{64}\z/

        module_function

        # Decodes an address to its public key as 64 uppercase hex characters.
        sig { params(address: T.untyped).returns(String) }
        def to_public_key(address)
          unless address.is_a?(String) && PATTERN.match?(address)
            Kernel.raise ArgumentError, "Invalid Nano address: #{address.inspect}"
          end

          encoded = address.split("_", 2).fetch(1)
          public_key = [decode(encoded.slice(0, 52).to_s).to_s(16).rjust(64, "0")].pack("H*")
          unless decode(encoded.slice(52, 8).to_s) == checksum(public_key)
            Kernel.raise ArgumentError, "Invalid Nano address checksum: #{address}"
          end

          public_key.unpack1("H*").upcase
        end

        # Encodes a public key (64 hex characters) as a `nano_` address.
        sig { params(public_key: T.untyped).returns(String) }
        def from_public_key(public_key)
          unless public_key.is_a?(String) && PUBLIC_KEY_PATTERN.match?(public_key)
            Kernel.raise ArgumentError, "Invalid Nano public key: #{public_key.inspect}"
          end

          bytes = [public_key].pack("H*")
          "nano_#{encode(public_key.to_i(16), 52)}#{encode(checksum(bytes), 8)}"
        end

        # True when the address is well formed and its checksum verifies.
        sig { params(address: T.untyped).returns(T::Boolean) }
        def valid?(address)
          to_public_key(address)
          true
        rescue ArgumentError
          false
        end

        # True when both addresses name the same account.
        sig { params(a: T.untyped, b: T.untyped).returns(T::Boolean) }
        def same_account?(a, b)
          to_public_key(a) == to_public_key(b)
        rescue ArgumentError
          false
        end

        # Canonical `nano_` form of a `nano_` or `xrb_` address.
        sig { params(address: T.untyped).returns(String) }
        def normalize(address)
          from_public_key(to_public_key(address))
        end

        # BLAKE2b-40 of the public key, read with its byte order reversed.
        sig { params(public_key: String).returns(Integer) }
        def checksum(public_key)
          Blake2b.digest(public_key, 5).reverse.unpack1("H*").to_i(16)
        end

        sig { params(value: String).returns(Integer) }
        def decode(value)
          value.each_char.reduce(0) { |acc, char| (acc << 5) | T.must(ALPHABET.index(char)) }
        end

        sig { params(value: Integer, length: Integer).returns(String) }
        def encode(value, length)
          Array.new(length) { |i| ALPHABET[(value >> (5 * (length - 1 - i))) & 31] }.join
        end

        private_class_method :checksum, :decode, :encode
      end
    end
  end
end

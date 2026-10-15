# frozen_string_literal: true

require "test_helper"
require "openssl"

class TestNanoAddress < Minitest::Test
  Address = Mpp::Methods::Nano::Address
  Blake2b = Mpp::Methods::Nano::Blake2b

  # Nano genesis account.
  GENESIS = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
  GENESIS_KEY = "E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA"

  def test_decodes_an_address_to_its_public_key
    assert_equal GENESIS_KEY, Address.to_public_key(GENESIS)
    assert_equal "9253DFDF9C8C6E9C6A77284A0044EF4A40248428F7F790E4F1E047015DE4B5E1",
      Address.to_public_key("nano_36kmuzhss55gmjo9gc4c134gykk16k44jxzqk5kh5r4917gybfh3f7enradc")
  end

  def test_encodes_a_public_key_in_either_casing
    assert_equal GENESIS, Address.from_public_key(GENESIS_KEY)
    assert_equal GENESIS, Address.from_public_key(GENESIS_KEY.downcase)
  end

  def test_treats_the_legacy_xrb_prefix_as_the_same_account
    legacy = GENESIS.sub("nano_", "xrb_")

    assert Address.valid?(legacy)
    assert Address.same_account?(legacy, GENESIS)
    assert_equal GENESIS, Address.normalize(legacy)
  end

  def test_rejects_a_bad_checksum
    tampered = "#{GENESIS[0...-1]}1"

    refute Address.valid?(tampered)
    refute Address.same_account?(tampered, GENESIS)
    error = assert_raises(ArgumentError) { Address.to_public_key(tampered) }
    assert_match(/checksum/, error.message)
  end

  def test_rejects_malformed_addresses
    refute Address.valid?(GENESIS.sub("nano_", "ban_"))
    refute Address.valid?(GENESIS[0...-1])
    refute Address.valid?(GENESIS.sub("3t6k", "3t6l"))
    refute Address.valid?(GENESIS.sub("nano_3", "nano_4"))
    refute Address.valid?(nil)
    assert_raises(ArgumentError) { Address.from_public_key("00") }
  end

  def test_blake2b_matches_rfc7693_vector
    assert_equal "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" \
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
      Blake2b.digest("abc").unpack1("H*")
  end

  def test_blake2b_matches_openssl_across_block_boundaries
    [0, 1, 127, 128, 129, 255, 256, 257, 1000].each do |length|
      data = (0...length).map { |i| (i * 7) % 256 }.pack("C*")
      assert_equal OpenSSL::Digest.digest("BLAKE2b512", data), Blake2b.digest(data), "length #{length}"
    end
  end

  def test_blake2b_rejects_unsupported_sizes
    assert_raises(ArgumentError) { Blake2b.digest("abc", 0) }
    assert_raises(ArgumentError) { Blake2b.digest("abc", 65) }
  end
end

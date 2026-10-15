# frozen_string_literal: true

require "test_helper"

class TestNanoClientMethod < Minitest::Test
  RECIPIENT = "nano_36kmuzhss55gmjo9gc4c134gykk16k44jxzqk5kh5r4917gybfh3f7enradc"
  PAYER = "nano_3c8gam3sqzueg78i6qpmrcbxhpkrazgrdspib3634b8ekcqde44xn8n36wdw"
  HASH = "AF76DB116540806369252C2FEF3E4368B0180DBB61450DD83041A985AB66802F"

  def challenge
    method = Mpp::Methods::Nano.charge(rpc: ->(_action, _params) { {} })
    handler = Mpp::Server::MppHandler.new(method: method, realm: "api.example.com", secret_key: "secret")
    handler.charge(nil, "0.001", recipient: RECIPIENT)
  end

  def test_sends_the_challenged_payment_and_returns_its_hash
    sent = nil
    client = Mpp::Methods::Nano::ClientMethod.new(
      send_payment: lambda { |**args|
        sent = args
        HASH.downcase
      },
      account: PAYER.sub("nano_", "xrb_")
    )
    issued = challenge

    credential = client.create_credential(issued)

    assert_equal "nano", client.name
    assert_equal "1000000000000000000000000000", sent[:amount]
    assert_equal RECIPIENT, sent[:recipient]
    assert_equal "address", sent[:binding]
    assert_equal "nano:mainnet", sent[:network]
    assert_same issued, sent[:challenge]
    assert_equal({"type" => "hash", "hash" => HASH}, credential.payload)
    assert_equal "did:pkh:nano:mainnet:#{PAYER}", credential.source
    assert_equal issued.id, credential.challenge.id
  end

  def test_omits_source_without_an_account
    client = Mpp::Methods::Nano::ClientMethod.new(send_payment: ->(**) { HASH })

    assert_nil client.create_credential(challenge).source
  end

  def test_rejects_an_invalid_hash_from_the_wallet
    client = Mpp::Methods::Nano::ClientMethod.new(send_payment: ->(**) { "not-a-hash" })

    assert_raises(ArgumentError) { client.create_credential(challenge) }
  end

  def test_requires_a_callable
    assert_raises(ArgumentError) { Mpp::Methods::Nano::ClientMethod.new(send_payment: nil) }
  end
end

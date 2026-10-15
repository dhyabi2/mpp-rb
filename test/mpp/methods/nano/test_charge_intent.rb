# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class TestNanoChargeIntent < Minitest::Test
  SECRET = "test-nano-secret"
  REALM = "api.example.com"
  RECIPIENT = "nano_36kmuzhss55gmjo9gc4c134gykk16k44jxzqk5kh5r4917gybfh3f7enradc"
  PAYER = "nano_3c8gam3sqzueg78i6qpmrcbxhpkrazgrdspib3634b8ekcqde44xn8n36wdw"
  OTHER = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
  HASH = "AF76DB116540806369252C2FEF3E4368B0180DBB61450DD83041A985AB66802F"
  MILLI = "1000000000000000000000000000" # 0.001 XNO in raw

  # Stands in for a Nano node: returns queued block_info responses.
  class FakeRpc
    attr_reader :calls

    def initialize(*responses)
      @responses = responses
      @calls = []
    end

    def call(action, params)
      @calls << [action, params]
      response = (@responses.length > 1) ? @responses.shift : @responses.first
      raise response if response.is_a?(Exception)

      response
    end
  end

  def block(amount: MILLI, recipient: RECIPIENT, confirmed: "true", subtype: "send", type: "state", account: PAYER)
    {
      "block_account" => account,
      "amount" => amount,
      "balance" => "2499000000000000000000000000000",
      "confirmed" => confirmed,
      "subtype" => subtype,
      "contents" => {"type" => type, "link_as_account" => recipient}
    }
  end

  def setup_handler(rpc, binding: "address", store: Mpp::MemoryStore.new)
    @rpc = rpc
    @method = Mpp::Methods::Nano.charge(binding: binding, rpc: rpc, store: store)
    @handler = Mpp::Server::MppHandler.new(method: @method, realm: REALM, secret_key: SECRET)
  end

  def charge(authorization, amount: "0.001", recipient: RECIPIENT, **opts)
    @handler.charge(authorization, amount, recipient: recipient, **opts)
  end

  def credential_for(challenge, hash: HASH, source: nil, payload: nil)
    Mpp::Credential.new(
      challenge: challenge.to_echo,
      payload: payload || {"type" => "hash", "hash" => hash},
      source: source
    ).to_authorization
  end

  def pay(hash: HASH, source: nil, **opts)
    challenge = charge(nil, **opts)
    charge(credential_for(challenge, hash: hash, source: source), **opts)
  end

  def test_challenge_request_is_issued_in_raw
    setup_handler(FakeRpc.new(block))
    challenge = charge(nil, recipient: RECIPIENT.sub("nano_", "xrb_"), external_id: "order-1")

    assert_equal "nano", challenge.method
    assert_equal "charge", challenge.intent
    assert_equal(
      {
        "amount" => MILLI,
        "currency" => "XNO",
        "externalId" => "order-1",
        "methodDetails" => {"binding" => "address", "network" => "nano:mainnet"},
        "recipient" => RECIPIENT
      },
      challenge.request
    )
    assert_empty @rpc.calls
  end

  def test_factory_validates_options
    assert_raises(ArgumentError) { Mpp::Methods::Nano.charge(binding: "memo") }
    assert_raises(ArgumentError) { Mpp::Methods::Nano.charge(recipient: "nano_invalid") }
    assert_raises(ArgumentError) { Mpp::Methods::Nano.charge(rpc: Object.new) }
    assert_raises(ArgumentError) { Mpp::Methods::Nano.charge(on_payment_success: Object.new) }
    assert_equal "http://127.0.0.1:7076", Mpp::Methods::Nano::DEFAULT_RPC_URL
  end

  def test_refuses_other_currencies_and_zero_amounts
    setup_handler(FakeRpc.new(block))

    assert_raises(ArgumentError) { charge(nil, currency: "USD") }
    assert_raises(ArgumentError) { charge(nil, amount: "0") }
    assert_raises(ArgumentError) { charge(nil, recipient: "nano_invalid") }
  end

  def test_accepts_a_confirmed_send
    setup_handler(FakeRpc.new(block))
    credential, receipt = pay(external_id: "order-1")

    assert_equal "success", receipt.status
    assert_equal "nano", receipt.method
    assert_equal HASH, receipt.reference
    assert_equal "order-1", receipt.external_id
    assert_equal HASH, credential.payload["hash"]
    assert_equal ["block_info", {"hash" => HASH, "json_block" => "true"}], @rpc.calls.first
  end

  def test_accepts_overpayment_and_a_legacy_recipient_form_in_address_binding
    setup_handler(FakeRpc.new(block(amount: "2#{MILLI}", recipient: RECIPIENT.sub("nano_", "xrb_"))))
    _credential, receipt = pay

    assert_equal HASH, receipt.reference
  end

  def test_requires_the_exact_amount_in_amount_binding
    unique = "1000000000000000000000004217"
    setup_handler(FakeRpc.new(block(amount: "1000000000000000000000004218")), binding: "amount")
    challenge = charge(nil, amount: "0.001000000000000000000000004217")

    assert_equal unique, challenge.request["amount"]
    assert_equal "amount", challenge.request.dig("methodDetails", "binding")
    error = assert_raises(Mpp::VerificationFailedError) do
      charge(credential_for(challenge), amount: "0.001000000000000000000000004217")
    end
    assert_match(/amount mismatch/, error.message)

    setup_handler(FakeRpc.new(block(amount: unique)), binding: "amount")
    _credential, receipt = pay(amount: "0.001000000000000000000000004217")
    assert_equal HASH, receipt.reference
  end

  def test_rejects_underpayment
    setup_handler(FakeRpc.new(block(amount: "999999999999999999999999999")))

    assert_raises(Mpp::PaymentInsufficientError) { pay }
  end

  def test_rejects_a_block_that_is_not_a_send
    setup_handler(FakeRpc.new(block(subtype: "receive")))
    assert_raises(Mpp::VerificationFailedError) { pay }

    setup_handler(FakeRpc.new(block(type: "send")))
    assert_raises(Mpp::VerificationFailedError) { pay }
  end

  def test_rejects_a_send_to_another_account
    setup_handler(FakeRpc.new(block(recipient: OTHER)))
    error = assert_raises(Mpp::VerificationFailedError) { pay }

    assert_match(/recipient mismatch/, error.message)
  end

  def test_unconfirmed_block_is_not_consumed_and_can_be_retried
    setup_handler(FakeRpc.new(block(confirmed: "false"), block, block))
    challenge = charge(nil)
    authorization = credential_for(challenge)

    error = assert_raises(Mpp::VerificationFailedError) { charge(authorization) }
    assert_match(/not confirmed/, error.message)

    _credential, receipt = charge(authorization)
    assert_equal HASH, receipt.reference
  end

  def test_rejects_a_replayed_hash_in_any_casing
    setup_handler(FakeRpc.new(block))
    pay

    assert_raises(Mpp::InvalidChallengeError) { pay }
    assert_raises(Mpp::InvalidChallengeError) { pay(hash: HASH.downcase) }
  end

  def test_rejects_a_second_payment_for_the_same_challenge
    other_hash = "B" * 64
    setup_handler(FakeRpc.new(block))
    challenge = charge(nil)
    charge(credential_for(challenge))

    error = assert_raises(Mpp::InvalidChallengeError) { charge(credential_for(challenge, hash: other_hash)) }
    assert_match(/already been answered/, error.message)
  end

  def test_a_shared_store_rejects_replays_across_instances
    store = Mpp::MemoryStore.new
    setup_handler(FakeRpc.new(block), store: store)
    pay

    setup_handler(FakeRpc.new(block), store: store)
    assert_raises(Mpp::InvalidChallengeError) { pay }
  end

  def test_rejects_malformed_payloads_before_calling_the_node
    setup_handler(FakeRpc.new(block))
    challenge = charge(nil)

    assert_raises(Mpp::MalformedCredentialError) { charge(credential_for(challenge, hash: "1234")) }
    assert_raises(Mpp::MalformedCredentialError) do
      charge(credential_for(challenge, payload: {"type" => "transaction", "hash" => HASH}))
    end
    assert_empty @rpc.calls
  end

  def test_checks_a_declared_source
    setup_handler(FakeRpc.new(block))
    _credential, receipt = pay(source: "did:pkh:nano:mainnet:#{PAYER.sub("nano_", "xrb_")}")
    assert_equal HASH, receipt.reference

    setup_handler(FakeRpc.new(block))
    assert_raises(Mpp::VerificationFailedError) { pay(source: "did:pkh:nano:mainnet:#{OTHER}") }

    setup_handler(FakeRpc.new(block))
    assert_raises(Mpp::VerificationFailedError) { pay(source: "did:pkh:nano:beta:#{PAYER}") }
  end

  def test_node_errors_fail_verification
    setup_handler(FakeRpc.new({"error" => "Block not found"}))
    error = assert_raises(Mpp::VerificationFailedError) { pay }
    assert_match(/Block not found/, error.message)

    setup_handler(FakeRpc.new(Errno::ECONNREFUSED.new))
    error = assert_raises(Mpp::VerificationFailedError) { pay }
    assert_match(/RPC request failed/, error.message)

    setup_handler(FakeRpc.new(block(amount: "1e27")))
    assert_raises(Mpp::VerificationFailedError) { pay }

    setup_handler(FakeRpc.new(nil))
    assert_raises(Mpp::VerificationFailedError) { pay }
  end

  def test_validate_does_not_consume
    store = Mpp::MemoryStore.new
    setup_handler(FakeRpc.new(block), store: store)
    challenge = charge(nil)
    credential = Mpp::Credential.new(challenge: challenge.to_echo, payload: {"type" => "hash", "hash" => HASH.downcase})
    intent = @method.intents.fetch("charge")

    validation = intent.validate(credential, challenge.request)

    assert_equal "nano", validation.method
    assert_equal({account: PAYER, amount: MILLI, hash: HASH}, validation.details)
    assert_nil store.get("mpp:nano:charge:#{HASH}")
    assert_equal HASH, intent.broadcast(credential, challenge.request).reference
    assert_equal challenge.id, store.get("mpp:nano:charge:#{HASH}")
  end

  def test_composes_next_to_other_methods
    setup_handler(FakeRpc.new(block))
    stripe = Mpp::Methods::Stripe.stripe(secret_key: "sk_test", network_id: "net", payment_methods: ["card"])
    server = Mpp::Server::MppHandler.new(methods: [stripe, @method], realm: REALM, secret_key: SECRET)

    composed = server.compose(
      [stripe, {amount: "0.01", currency: "usd"}],
      [@method, {amount: "0.001", recipient: RECIPIENT}]
    )
    result = composed.call(authorization: nil)

    assert result.payment_required?
    assert_equal ["stripe", "nano"], result.challenges.map(&:method)
  end

  def test_default_rpc_posts_block_info_to_the_node
    stub = stub_request(:post, "http://node.example:7076/")
      .with(body: {"hash" => HASH, "json_block" => "true", "action" => "block_info"})
      .to_return(status: 200, body: JSON.generate(block))
    rpc = Mpp::Methods::Nano::Rpc.new(url: "http://node.example:7076/")

    assert_equal block, rpc.call("block_info", {"hash" => HASH, "json_block" => "true"})
    assert_requested stub
  end

  def test_default_rpc_reports_http_and_parse_failures
    rpc = Mpp::Methods::Nano::Rpc.new(url: "http://node.example:7076/")

    stub_request(:post, "http://node.example:7076/").to_return(status: 502, body: "")
    assert_raises(Mpp::VerificationError) { rpc.call("block_info", {}) }

    stub_request(:post, "http://node.example:7076/").to_return(status: 200, body: "not json")
    assert_raises(Mpp::VerificationError) { rpc.call("block_info", {}) }
  end
end

# typed: true
# frozen_string_literal: true

module Mpp
  module Methods
    # Nano (XNO) charge method per draft-nano-charge-00. The credential is the
    # hash of a confirmed send block, verified against a Nano node RPC.
    module Nano
      CURRENCY = "XNO"
      DECIMALS = 30
      DEFAULT_NETWORK = "nano:mainnet"
      # Default RPC port of a locally run Nano node.
      DEFAULT_RPC_URL = "http://127.0.0.1:7076"
      BINDINGS = ["address", "amount"].freeze

      autoload :Address, "mpp/methods/nano/address"
      autoload :Blake2b, "mpp/methods/nano/blake2b"
      autoload :ChargeIntent, "mpp/methods/nano/charge_intent"
      autoload :ClientMethod, "mpp/methods/nano/client_method"
      autoload :NanoMethod, "mpp/methods/nano/nano_method"
      autoload :Rpc, "mpp/methods/nano/rpc"

      # Factory for a server-side Nano charge method.
      #
      # recipient: default `nano_` address; may instead be passed per charge.
      # binding:   "address" (a fresh recipient per challenge, recommended) or
      #            "amount" (a unique exact amount per challenge on one address).
      # rpc_url:   Nano node RPC endpoint; or pass `rpc:` (anything with
      #            `call(action, params) -> Hash`).
      # store:     atomic store for consumed block hashes and challenges; use a
      #            shared store when several processes serve the realm.
      def self.charge(recipient: nil, binding: "address", network: DEFAULT_NETWORK,
        rpc_url: DEFAULT_RPC_URL, rpc: nil, store: Mpp::MemoryStore.new,
        on_payment_success: nil, can_offer: nil)
        method = NanoMethod.new(
          recipient: recipient,
          binding: binding,
          network: network,
          on_payment_success: on_payment_success,
          can_offer: can_offer
        )
        method.intents = {"charge" => ChargeIntent.new(rpc_url: rpc_url, rpc: rpc, store: store)}
        method
      end
    end
  end
end

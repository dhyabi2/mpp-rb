# typed: false
# frozen_string_literal: true

module Mpp
  module Methods
    module Nano
      # Client-side Nano method. It holds no keys: `send_payment` publishes a
      # send block with whatever wallet the caller uses and returns its hash.
      # Return once the block is confirmed, since servers refuse unconfirmed
      # blocks.
      #
      #   Mpp::Methods::Nano::ClientMethod.new(
      #     send_payment: ->(amount:, recipient:, **) { wallet.send(recipient, amount) }
      #   )
      class ClientMethod
        attr_reader :name

        # account: optional payer address, sent as a did:pkh source.
        def initialize(send_payment:, account: nil)
          raise ArgumentError, "send_payment must be callable" unless send_payment.respond_to?(:call)

          @name = "nano"
          @send_payment = send_payment
          @account = account.nil? ? nil : Address.normalize(account)
        end

        def create_credential(challenge)
          raise ArgumentError, "Unsupported intent: #{challenge.intent}" unless challenge.intent == "charge"

          request = challenge.request
          method_details = request["methodDetails"]
          method_details = {} unless method_details.is_a?(Hash)
          network = method_details["network"] || DEFAULT_NETWORK

          hash = @send_payment.call(
            amount: request["amount"],
            recipient: request["recipient"],
            binding: method_details["binding"] || "address",
            network: network,
            challenge: challenge
          )
          unless hash.is_a?(String) && ChargeIntent::HASH_PATTERN.match?(hash)
            raise ArgumentError, "Invalid Nano block hash: #{hash.inspect}"
          end

          Mpp::Credential.new(
            challenge: challenge.to_echo,
            payload: {"type" => "hash", "hash" => hash.upcase},
            source: @account && "did:pkh:#{network}:#{@account}"
          )
        end
      end
    end
  end
end

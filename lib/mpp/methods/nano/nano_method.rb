# typed: false
# frozen_string_literal: true

module Mpp
  module Methods
    module Nano
      # Server-side Nano payment method. Amounts are given in XNO and issued in
      # raw (1 XNO = 10^30 raw).
      class NanoMethod
        attr_reader :name, :currency, :recipient, :decimals, :binding, :network, :on_payment_success
        attr_accessor :intents

        def initialize(recipient: nil, binding: "address", network: DEFAULT_NETWORK,
          on_payment_success: nil, can_offer: nil)
          unless BINDINGS.include?(binding)
            raise ArgumentError, "binding must be one of: #{BINDINGS.join(", ")}"
          end
          unless network.is_a?(String) && !network.empty?
            raise ArgumentError, "network must be a non-empty string"
          end
          if !on_payment_success.nil? && !on_payment_success.respond_to?(:call)
            raise ArgumentError, "on_payment_success must be callable"
          end
          if !can_offer.nil? && !can_offer.respond_to?(:call)
            raise ArgumentError, "can_offer must be callable"
          end

          @name = "nano"
          @currency = CURRENCY
          @recipient = recipient.nil? ? nil : Address.normalize(recipient)
          @decimals = DECIMALS
          @binding = binding
          @network = network
          @on_payment_success = on_payment_success
          @can_offer = can_offer
          @intents = {}
        end

        def can_offer?(request)
          return true unless @can_offer

          @can_offer.call(request)
        end

        # Validates the canonical request and injects Nano methodDetails.
        def transform_request(request, _credential)
          unless request["currency"] == CURRENCY
            raise ArgumentError, "Nano charges must use currency #{CURRENCY}"
          end
          unless Integer(request["amount"].to_s, 10).positive?
            raise ArgumentError, "Nano charge amount must be positive"
          end

          method_details = request.fetch("methodDetails", {})
          method_details = {} unless method_details.is_a?(Hash)
          method_details["binding"] = @binding
          method_details["network"] = @network

          request.merge(
            "methodDetails" => method_details,
            "recipient" => Address.normalize(request["recipient"])
          )
        end
      end
    end
  end
end

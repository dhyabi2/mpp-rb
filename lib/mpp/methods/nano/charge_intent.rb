# typed: false
# frozen_string_literal: true

require "time"

module Mpp
  module Methods
    module Nano
      # Server-side Nano charge intent (draft-nano-charge-00).
      #
      # The credential is the hash of a send block the client has already
      # published. It is checked with one `block_info` call to a Nano node: the
      # block must be a confirmed state `send` to the challenged recipient for
      # at least the challenged amount (exactly the amount with
      # `binding: "amount"`). Each block hash and each challenge is accepted
      # once. An unconfirmed block is refused without being consumed, so the
      # same credential can be presented again once it confirms.
      #
      # The node is trusted to report confirmation; prefer one you operate.
      class ChargeIntent
        HASH_PATTERN = /\A\h{64}\z/
        RAW_PATTERN = /\A\d+\z/

        attr_reader :name

        def initialize(rpc_url: DEFAULT_RPC_URL, rpc: nil, store: Mpp::MemoryStore.new)
          raise ArgumentError, "store is required" if store.nil?
          raise ArgumentError, "rpc must respond to #call" if !rpc.nil? && !rpc.respond_to?(:call)

          @name = "charge"
          @rpc = rpc || Rpc.new(url: rpc_url)
          @store = store
        end

        # @deprecated Use #validate followed by #broadcast.
        def verify(credential, request)
          validate(credential, request)
          broadcast(credential, request)
        end

        def validate(credential, request)
          check_expiry(credential)
          hash = credential_hash(credential)
          if @store.get(hash_store_key(hash))
            raise Mpp::InvalidChallengeError.new(
              challenge_id: credential.challenge.id,
              reason: "block hash has already been used"
            )
          end

          details = verify_block(hash, request, credential)

          Mpp::Validation.new(
            challenge: credential.challenge,
            credential: credential,
            details: details,
            intent: name,
            method: "nano",
            request: request,
            source: credential.source
          )
        end

        def broadcast(credential, request)
          # Revalidate rather than trust an earlier #validate call; nothing is
          # consumed unless every check passes.
          validation = validate(credential, request)
          hash = validation.details.fetch(:hash)
          challenge_key = challenge_store_key(credential.challenge.id)

          unless @store.put_if_absent(challenge_key, hash)
            raise Mpp::InvalidChallengeError.new(
              challenge_id: credential.challenge.id,
              reason: "challenge has already been answered"
            )
          end
          # A confirmed send never stops being valid, so the hash is kept.
          unless @store.put_if_absent(hash_store_key(hash), credential.challenge.id)
            @store.delete(challenge_key)
            raise Mpp::InvalidChallengeError.new(
              challenge_id: credential.challenge.id,
              reason: "block hash has already been used"
            )
          end

          Mpp::Receipt.success(hash, method: "nano", external_id: request["externalId"])
        end

        private

        def check_expiry(credential)
          challenge_expires = credential.challenge.expires
          return unless challenge_expires

          expires = Time.iso8601(challenge_expires.gsub("Z", "+00:00"))
          raise Mpp::VerificationError, "Request has expired" if expires < Time.now.utc
        end

        def credential_hash(credential)
          payload = credential.payload
          unless payload.is_a?(Hash) && payload["type"] == "hash"
            raise Mpp::MalformedCredentialError.new(reason: "payload type must be \"hash\"")
          end

          hash = payload["hash"]
          unless hash.is_a?(String) && HASH_PATTERN.match?(hash)
            raise Mpp::MalformedCredentialError.new(reason: "block hash must be 64 hexadecimal characters")
          end

          hash.upcase
        end

        def verify_block(hash, request, credential)
          method_details = request["methodDetails"]
          method_details = {} unless method_details.is_a?(Hash)
          binding = method_details["binding"] || "address"
          network = method_details["network"] || DEFAULT_NETWORK
          required = Integer(request["amount"].to_s, 10)

          block = fetch_block(hash)

          contents = block["contents"]
          unless contents.is_a?(Hash) && contents["type"] == "state" && block["subtype"] == "send"
            raise Mpp::VerificationFailedError.new(reason: "Nano block is not a send block")
          end

          unless Address.same_account?(contents["link_as_account"], request["recipient"])
            raise Mpp::VerificationFailedError.new(reason: "Nano send recipient mismatch")
          end

          amount = block["amount"]
          unless amount.is_a?(String) && RAW_PATTERN.match?(amount)
            raise Mpp::VerificationFailedError.new(reason: "Nano node returned a malformed amount")
          end

          sent = Integer(amount, 10)
          if binding == "amount" && sent != required
            raise Mpp::VerificationFailedError.new(reason: "Nano send amount mismatch")
          end
          if sent < required
            raise Mpp::PaymentInsufficientError.new(reason: "Nano send amount is below the charge")
          end

          unless block["confirmed"] == "true"
            raise Mpp::VerificationFailedError.new(reason: "Nano block is not confirmed yet")
          end

          account = block["block_account"]
          verify_source(credential.source, network, account)

          {account: account, amount: amount, hash: hash}
        end

        def fetch_block(hash)
          block = begin
            @rpc.call("block_info", {"hash" => hash, "json_block" => "true"})
          rescue Mpp::PaymentError
            raise
          rescue => e
            raise Mpp::VerificationFailedError.new(reason: "Nano RPC request failed: #{e.message}")
          end

          unless block.is_a?(Hash)
            raise Mpp::VerificationFailedError.new(reason: "Nano RPC returned a malformed response")
          end
          if block.key?("error")
            raise Mpp::VerificationFailedError.new(reason: "Nano block lookup failed: #{block["error"]}")
          end

          block
        end

        def verify_source(source, network, account)
          return if source.nil?

          prefix = "did:pkh:#{network}:"
          unless source.is_a?(String) && source.start_with?(prefix) && Address.same_account?(source.delete_prefix(prefix), account)
            raise Mpp::VerificationFailedError.new(reason: "Nano send source mismatch")
          end
        end

        def hash_store_key(hash)
          "mpp:nano:charge:#{hash}"
        end

        def challenge_store_key(challenge_id)
          "mpp:nano:challenge:#{challenge_id}"
        end
      end
    end
  end
end

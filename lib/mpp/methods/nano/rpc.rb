# typed: false
# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

module Mpp
  module Methods
    module Nano
      # Client for the Nano node RPC (`POST {"action": ...}` JSON over HTTP).
      #
      # Any object responding to `call(action, params) -> Hash` can be passed to
      # ChargeIntent instead, for example to add authentication or retries.
      class Rpc
        DEFAULT_TIMEOUT = 10

        attr_reader :url

        def initialize(url: DEFAULT_RPC_URL, timeout: DEFAULT_TIMEOUT, http: nil)
          raise ArgumentError, "Nano rpc url is required" if url.nil? || url.to_s.empty?

          @url = url.to_s
          @timeout = timeout
          @http = http
        end

        # Performs one RPC action and returns the parsed response object.
        # Node-level errors (`{"error": ...}`) are returned to the caller.
        def call(action, params = {})
          uri = URI.parse(@url)
          http = @http || Net::HTTP.new(uri.host, uri.port)
          unless @http
            http.use_ssl = uri.scheme == "https"
            http.open_timeout = @timeout
            http.read_timeout = @timeout
          end

          request = Net::HTTP::Post.new(uri)
          request["Content-Type"] = "application/json"
          request.body = JSON.generate(params.merge("action" => action))

          response = http.request(request)
          unless response.is_a?(Net::HTTPSuccess)
            raise Mpp::VerificationError, "Nano RPC request failed: HTTP #{response.code}"
          end

          body = JSON.parse(response.body.to_s)
          raise Mpp::VerificationError, "Nano RPC returned a malformed response" unless body.is_a?(Hash)

          body
        rescue JSON::ParserError
          raise Mpp::VerificationError, "Nano RPC returned a malformed response"
        end
      end
    end
  end
end

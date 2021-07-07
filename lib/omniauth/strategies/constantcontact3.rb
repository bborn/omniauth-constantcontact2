require 'omniauth-oauth2'
require 'multi_json'
require 'multi_xml'

module OmniAuth
  module Strategies
    class ConstantContact3 < OmniAuth::Strategies::OAuth2
      option :name, "constantcontact"

      option :client_options, {
        :authorize_url => 'https://api.cc.email/v3/idfed',
        :token_url => 'https://idfed.constantcontact.com/as/token.oauth2'
      }

      def callback_url
        full_host + script_name + callback_path
      end

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token
        hash["expires"] = true
        hash
      end

    end
  end
end

OmniAuth.config.add_camelization 'constantcontact', 'ConstantContact3'

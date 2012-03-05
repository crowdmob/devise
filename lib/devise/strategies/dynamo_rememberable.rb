require 'devise/strategies/base'

module Devise
  module Strategies
    # Remember the user through dynamo db. This strategy is responsible
    # to verify whether there is a cookie with the remember token, and to
    # recreate the user from this cookie if it exists. Must be called *before*
    # authenticatable.
    class RememberableInDynamo < Authenticatable
      def store_session
        request.session_options[:id]
      end
    end
  end
end

Warden::Strategies.add(:dynamo_rememberable, Devise::Strategies::DynamoRememberable)
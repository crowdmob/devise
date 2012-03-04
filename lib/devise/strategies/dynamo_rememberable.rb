require 'devise/strategies/base'

module Devise
  module Strategies
    # Remember the user through dynamo db. This strategy is responsible
    # to verify whether there is a cookie with the remember token, and to
    # recreate the user from this cookie if it exists. Must be called *before*
    # authenticatable.
    class RememberableInDynamo < Authenticatable
      # A valid strategy for rememberable needs a remember token in the cookies.
      def valid?
        @dynamo_remember = nil
        dynamo_remember.present?
      end

      # To authenticate a user we deserialize the cookie and attempt finding
      # the record in the database. If the attempt fails, we pass to another
      # strategy handle the authentication.
      def authenticate!
        resource = mapping.to.serialize_from_dynamo(*dynamo_remember)

        if validate(resource)
          success!(resource)
        elsif !halted?
          cookies.delete(dynamo_remember_key)
          pass
        end
      end

    private

      def decorate(resource)
        super
        resource.extend_dynamo_remember_period = mapping.to.extend_dynamo_remember_period if resource.respond_to?(:extend_dynamo_remember_period=)
      end

      def dynamo_remember_me?
        true
      end

      def dynamo_remember_key
        "dynamo_remember_#{scope}_key"
      end

      def dynamo_remember
        @dynamo_remember ||= cookies.signed[dynamo_remember_key]
      end

    end
  end
end

Warden::Strategies.add(:dynamo_rememberable, Devise::Strategies::DynamoRememberable)
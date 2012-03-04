require 'devise/strategies/dynamo_rememberable'
require 'devise/hooks/dynamo_rememberable'
require 'devise/hooks/dynamo_forgetable'

module Devise
  module Models
    # Rememberable manages generating and clearing token for remember the user
    # from a saved cookie. Rememberable also has utility methods for dealing
    # with serializing the user into the cookie and back from the cookie, trying
    # to lookup the record based on the saved information.
    # You probably wouldn't use rememberable methods directly, they are used
    # mostly internally for handling the remember token.
    #
    # == Options
    #
    # Rememberable adds the following options in devise_for:
    #
    #   * +remember_for+: the time you want the user will be remembered without
    #     asking for credentials. After this time the user will be blocked and
    #     will have to enter his credentials again. This configuration is also
    #     used to calculate the expires time for the cookie created to remember
    #     the user. By default remember_for is 2.weeks.
    #
    #   * +extend_remember_period+: if true, extends the user's remember period
    #     when remembered via cookie. False by default.
    #
    #   * +rememberable_options+: configuration options passed to the created cookie.
    #
    # == Examples
    #
    #   User.find(1).remember_me!  # regenerating the token
    #   User.find(1).forget_me!    # clearing the token
    #
    #   # generating info to put into cookies
    #   User.serialize_into_cookie(user)
    #
    #   # lookup the user based on the incoming cookie information
    #   User.serialize_from_cookie(cookie_string)
    module DynamoRememberable
      extend ActiveSupport::Concern

      attr_accessor :dynamo_remember_me, :extend_dynamo_remember_period

      def self.required_fields(klass)
        [:dynamo_remember_created_at, :dynamo_remember_key]
      end

      # Generate a new remember token and save the record without validations
      # unless remember_across_browsers is true and the user already has a valid token.
      def dynamo_remember_me!(extend_period=false)
        self.dynamo_remember_key = self.class.dynamo_remember if generate_dynamo_remember_key?
        self.dynamo_remember_created_at = Time.now.utc if generate_dynamo_remember_timestamp?(extend_period)
        save(:validate => false)
      end

      # If the record is persisted, remove the remember token (but only if
      # it exists), and save the record without validations.
      def dynamo_forget_me!
        return unless persisted?
        self.dynamo_remember_token = nil if respond_to?(:dynamo_remember_token=)
        self.dynamo_remember_created_at = nil
        save(:validate => false)
      end

      # Remember token should be expired if expiration time not overpass now.
      def dynamo_remember_expired?
        dynamo_remember_created_at.nil? || (dynamo_remember_expires_at <= Time.now.utc)
      end

      # Remember token expires at created time + remember_for configuration
      def dynamo_remember_expires_at
        dynamo_remember_created_at + self.class.dynamo_remember_for
      end

      def dynamo_rememberable_value
        if respond_to?(:remember_token)
          dynamo_remember_token
        elsif salt = authenticatable_salt
          salt
        else
          raise "authenticable_salt returned nil for the #{self.class.name} model. " \
            "In order to use rememberable, you must ensure a password is always set " \
            "or have a remember_token column in your model or implement your own " \
            "rememberable_value in the model with custom logic."
        end
      end

      def dynamo_rememberable_options
        self.class.dynamo_rememberable_options
      end

    protected

      def generate_dynamo_remember_token?
        respond_to?(:remember_token) && dynamo_remember_expired?
      end

      # Generate a timestamp if extend_remember_period is true, if no remember_token
      # exists, or if an existing remember token has expired.
      def generate_dynamo_remember_timestamp?(extend_period) #:nodoc:
        extend_period || dynamo_remember_created_at.nil? || dynamo_remember_expired?
      end

      module ClassMethods
        # Create the cookie key using the record id and remember_token
        def serialize_into_dynamo(record)
          #WRITE TO DYNAMO
          [record.to_key, record.dynamo_rememberable_value]
        end

        # Recreate the user based on the stored cookie
        def serialize_from_dynamo(id, dynamo_remember_key)
          #record = to_adapter.get(id)
          # DYNAMO READ
          record if record && record.dynamo_rememberable_value == dynamo_remember_token && !record.dynamo_remember_expired?
        end

        # Generate a token checking if one does not already exist in the database.
        def dynamo_remember_token
          generate_token(:dynamo_remember_key)
        end

        Devise::Models.config(self, :dynamo_remember_for, :extend_dynamo_remember_period, :dynamo_rememberable_options)
      end
    end
  end
end

require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    # Default strategy for signing in a user, based on his email and password in the database.
    class PasswordlessAuthenticatable < Authenticatable
      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)

        if resource.respond_to?(:password_initialized)
          if resource.password_initialized
            resource = valid_password? && resource
          
            if validate(resource){ resource.valid_password?(password) }
              resource.after_database_authentication
              success!(resource)
            elsif !halted?
              fail(:invalid)
            end
          end
          else resource
            resource.after_database_authentication
            success!(resource)
          end
        else
          fail(:invalid)
        end
      end
    end
  end
end

Warden::Strategies.add(:passwordless_authenticatable, Devise::Strategies::PasswordlessAuthenticatable)

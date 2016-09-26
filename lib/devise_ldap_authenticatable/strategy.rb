require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable

      def domains_configuration
        @domains_configuration ||= begin
          path = "#{Rails.root}/config/ldap.yml"
          YAML.load(ERB.new(File.read(path)).result)[Rails.env]['domains']
        end
      end

      def domains
        domains_configuration.keys
      end

      def find_database_user(username)
        User.find_by username: authentication_hash[:username]
      end

      def user_domain(username)
        find_database_user(username).try :domain
      end

      def find_for_ldap_authentication_through_domains(authentication_hash)
        resource    = nil
        domains.each do |domain|
          begin
            Rails.logger.info "LDAP: looking in #{domain} domain..."
            RequestStore.store[:user_domain] = domain

            resource = mapping.to.find_for_ldap_authentication(authentication_hash)

            next unless resource.try(:ldap_entry) # next if not exist in the current domain
            Rails.logger.info "LDAP: found in #{domain} domain..."

            # update belonging domain
            if resource.persisted?
              resource.update_column :domain, domain
            else
              resource.domain = domain
            end
            break #the first domain found wins
          rescue => e
            Rails.logger.warn e
          end
        end
        resource
      end

      def find_for_ldap_authentication(authentication_hash)

        # if a domain is specified in the user model that one will be used
        resource = if domain = user_domain(authentication_hash[:username])
          RequestStore.store[:user_domain] = domain
          mapping.to.find_for_ldap_authentication(authentication_hash)
        else
          find_for_ldap_authentication_through_domains(authentication_hash)
        end

        resource
      end

      # Tests whether the returned resource exists in the database and the
      # credentials are valid.  If the resource is in the database and the credentials
      # are valid, the user is authenticated.  Otherwise failure messages are returned
      # indicating whether the resource is not found in the database or the credentials
      # are invalid.
      def authenticate!
        resource = find_for_ldap_authentication(authentication_hash.merge(password: password))
        return fail(:invalid) unless resource

        if validate(resource) { resource.valid_ldap_authentication?(password) }
          # valid credential

          resource.after_ldap_authentication if resource.respond_to?(:after_ldap_authentication)
          return fail(resource.errors.full_messages.first) unless resource.valid?

          if resource.persisted?
            remember_me(resource)
            success!(resource)
          end

          if resource.new_record?
            if ::Devise.ldap_create_user
              resource.save!(validate: false)
              success!(resource)
            else
              return fail(:not_found_in_database)
            end
          end

        else
          # Invalid credentials
          return fail(:invalid)

        end
      rescue ActiveRecord::RecordInvalid => e
        msg = I18n.t('devise.failure.not_found_in_database') + " #{e}"
        return fail(msg)
      rescue => error
        Rails.logger.error { "LDAP AUTH ERROR while authenticating #{resource}: #{error}" }
        return fail
      end
    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)

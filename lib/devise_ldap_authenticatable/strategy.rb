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
            Rails.logger.info "LDAP: looking for #{domain} domain..."
            RequestStore.store[:user_domain] = domain
            # the following call returns:
            # 1) nil if authentication_hash does not countain a valid auth_key (:username in this case)
            # 2) an existing resource
            # 3) a brand new and persisted resource (auth success)
            # 4) a brand new and NOT persisted resource (auth fail or resource invalid)
            resource = mapping.to.find_for_ldap_authentication(authentication_hash)

            if resource.present?
              if resource.persisted?
                resource.update_column :domain, domain
              else
                resource.domain = domain
              end
              break
            end
          rescue => e
            Rails.logger.warn e
          end
        end
      end

      def find_for_ldap_authentication(authentication_hash)
        if user_domain = user_domain(authentication_hash[:username])
          RequestStore.store[:user_domain] = user_domain
          mapping.to.find_for_ldap_authentication(authentication_hash)
        else
          find_for_ldap_authentication_through_domains(authentication_hash)
        end
      end

      # Tests whether the returned resource exists in the database and the
      # credentials are valid.  If the resource is in the database and the credentials
      # are valid, the user is authenticated.  Otherwise failure messages are returned
      # indicating whether the resource is not found in the database or the credentials
      # are invalid.
      def authenticate!
        resource = mapping.to.find_for_ldap_authentication(authentication_hash.merge(password: password))

        return fail(:invalid) unless resource

        if resource.persisted?
          if validate(resource) { resource.valid_ldap_authentication?(password) }
            remember_me(resource)
            resource.after_ldap_authentication
            success!(resource)
          else
            return fail(:invalid) # Invalid credentials
          end
        end

        if resource.new_record?
          if validate(resource) { resource.valid_ldap_authentication?(password) }
            return fail(:unknown_email) if resource.errors[:email].present?
            return fail(:not_found_in_database) # Valid credentials
          else
            return fail(:invalid) # Invalid credentials
          end
        end
      end
    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)

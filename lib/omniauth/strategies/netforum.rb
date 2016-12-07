module OmniAuth
  module Strategies
    class Netforum < OmniAuth::Strategies::OAuth2
      option :name, 'netforum'

      option :client_options, {
        # :site => 'https://netforum.avectra.com',
        site: 'https://uat.netforumpro.com',
        authorize_url: '/eWeb/ValidateLogin.aspx',
        authentication_wsdl: '/xWeb/Signon.asmx?WSDL',
        user_info_wsdl: '/xweb/netFORUMXMLONDemand.asmx?WSDL',
        event_code: 'MUST BE SET',
        username: 'MUST BE SET',
        password: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        raw_info
      end

      extra do
        { :raw_info => raw_info }
      end

      def request_phase
        site = session['omniauth.params']['eventcode'] || client_event_code
        redirect authorize_url + "?ReturnURL=" + URI.encode(callback_url+"&Site=#{site}")
      end

      def callback_phase
        if request.params['ssoToken']
          self.access_token = {
            :token =>  request.params['ssoToken'],
            :token_expires => 60
          }
          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = if request.params['Site']
            '/' + get_slug(request.params['Site'])
          else
            request.params['origin']
          end
          call_app!
        else
          fail!(:invalid_credentials)
        end
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token])
      end

      def get_slug(event_code)
        Provider.find_by_event_code(event_code)&.account.slug
      end

      def get_user_info(access_token)
        auth_wsdl = options.client_options.site + options.client_options.authentication_wsdl
        user_info_wsdl = options.client_options.site + options.client_options.user_info_wsdl

        ::Netforum.configure do
          authentication_wsdl auth_wsdl
          on_demand_wsdl user_info_wsdl
        end

        if auth = ::Netforum.authenticate(client_username, client_password)
          customer_key = auth.get_customer_key(access_token)
          auth = ::Netforum.authenticate(client_username, client_password)
          on_demand = ::Netforum.on_demand(auth.authentication_token)
          customer = on_demand.get_customer_by_key(customer_key)

          {
            id: customer.customer_id,
            first_name: customer.ind_first_name,
            last_name: customer.ind_last_name,
            email: customer.email_address,
            cst_key: customer.cst_key,
            member_flag: customer.member_flag,
            membership: customer.membership,
            membership_status: customer.member_status
          }
        end
      end

      private

      def authorize_url
        "#{options.client_options.site}#{options.client_options.authorize_url}"
      end

      def client_event_code
        options.client_options.event_code
      end

      def client_username
        options.client_options.username
      end

      def client_password
        options.client_options.password
      end
    end
  end
end

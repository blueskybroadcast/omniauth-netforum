module OmniAuth
  module Strategies
    class Netforum < OmniAuth::Strategies::OAuth2

      option :name, 'netforum'

      option :authorize_params, {
        WebCode: 'LoginRequired'
      }

      option :client_options, {
        # :site => 'https://netforum.avectra.com',
        site: 'https://uat.netforumpro.com',
        authorize_url: '/eWeb/DynamicPage.aspx',
        authentication_wsdl: '/xWeb/Signon.asmx?WSDL',
        user_info_wsdl: '/xweb/netFORUMXMLONDemand.asmx?WSDL',
        username: 'MUST BE SET',
        password: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        raw_info
      end

      def request_phase
        site = session['omniauth.params']['eventcode']
        redirect client.auth_code.authorize_url({URL_success: callback_url + "?{ssoToken}", site: site}.merge(authorize_params))
      end

      def callback_phase
        if request.params['ssoToken']
          self.access_token = {
            :token =>  request.params['ssoToken'],
            :token_expires => 60
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + get_slug(request.params['Site'])
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
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token])
      end

      def get_slug(event_code)
        Account.find_by_event_code(event_code).slug
      end

      def get_user_info(access_token)
        auth_wsdl = options.client_options.site + options.client_options.authentication_wsdl
        user_info_wsdl = options.client_options.site + options.client_options.user_info_wsdl

        ::Netforum.configure do
          authentication_wsdl auth_wsdl
          on_demand_wsdl user_info_wsdl
        end

        if auth = ::Netforum.authenticate(options.client_options.username, options.client_options.password)
          customer_key = auth.get_customer_key(access_token)
          auth = ::Netforum.authenticate(options.client_options.username, options.client_options.password)
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
    end
  end
end

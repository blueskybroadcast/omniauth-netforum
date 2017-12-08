module OmniAuth
  module Strategies
    class Netforum < OmniAuth::Strategies::OAuth2
      option :name, 'netforum'

      option :app_options, { app_event_id: nil }

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
        { raw_info: raw_info }
      end

      def request_phase
        site = session['omniauth.params']['eventcode'] || client_event_code
        redirect authorize_url + "?Site=#{site}" + '&ReturnURL=' + URI.encode(callback_url + "?Site=#{site}")
      end

      def callback_phase
        slug = get_slug_from_params
        account = Account.find_by(slug: slug.gsub('/', ''))
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
        self.env['omniauth.app_event_id'] = @app_event.id

        if request.params['ssoToken']
          self.access_token = {
            :token =>  request.params['ssoToken'],
            :token_expires => 60
          }
          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = slug

          call_app!
        else
          @app_event.logs.create(level: 'error', text: "Netforum SSO Failure: 'ssoToken' parameter is absent!")
          @app_event.fail!

          fail!(:invalid_credentials)
        end
      rescue StandardError => e
        @app_event.try(:fail!)
        raise e
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token])
      end

      def get_slug_by_event_code(event_code)
        Provider.find_by_event_code(event_code)&.account.slug
      end

      def get_user_info(access_token)
        auth_wsdl = options.client_options.site + options.client_options.authentication_wsdl
        user_info_wsdl = options.client_options.site + options.client_options.user_info_wsdl

        ::Netforum.configure do
          authentication_wsdl auth_wsdl
          on_demand_wsdl user_info_wsdl
        end

        auth = ::Netforum.authenticate(client_username, client_password)
        create_request_and_response_logs('Authentication', auth)

        if auth
          customer_key = auth.get_customer_key(access_token)
          create_request_and_response_logs('GetCustomerKey', auth)

          auth = ::Netforum.authenticate(client_username, client_password)
          create_request_and_response_logs('Authentication', auth)

          on_demand = ::Netforum.on_demand(auth.authentication_token)
          customer = on_demand.get_customer_by_key(customer_key)
          create_request_and_response_logs('GetCustomerByKey', on_demand)

          info = {
            id: customer.customer_id,
            first_name: customer.ind_first_name,
            last_name: customer.ind_last_name,
            email: customer.email_address,
            cst_key: customer.cst_key,
            member_flag: customer.member_flag,
            membership: customer.membership,
            membership_status: customer.member_status,
            individual_code: customer.ind_int_code
          }

          @app_event.update(raw_data: {
            user_info: {
              uid: info[:id],
              email: info[:email],
              first_name: info[:first_name],
              last_name: info[:last_name]
            }
          })

          info
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

      def get_slug_from_params
        if request.params['Site']
          '/' + get_slug_by_event_code(request.params['Site'])
        else
          request.params['origin']
        end
      end

      def provider_name
        options.name
      end

      def create_request_and_response_logs(operation_name, client)
        if client.last_request
          filtered_request_body = client.last_request
                                        .body.inspect
                                        .gsub(/tns:password>.*<\/tns:password/, "tns:password>#{Provider::SECURITY_MASK}</tns:password")
                                        .gsub(/tns:Token>.*<\/tns:Token/, "tns:Token>#{Provider::SECURITY_MASK}</tem:Token")
                                        .gsub(/Token>.*<\/Token/, "Token>#{Provider::SECURITY_MASK}</Token")
          request_log_text = "#{provider_name.upcase} #{operation_name} Request:\nPOST #{client.last_request.url}, headers: #{client.last_request.headers}\n#{filtered_request_body}"
          @app_event.logs.create(level: 'info', text: request_log_text)

          response_log_text = "#{provider_name.upcase} #{operation_name} Response (code: #{client.last_response.code}):\n#{client.last_response.body}"
          response_log_level = client.last_response.code == 200 ? 'info' : 'error'
          @app_event.logs.create(level: response_log_level, text: response_log_text)
          @app_event.fail! if response_log_level == 'error'
        end
      end
    end
  end
end

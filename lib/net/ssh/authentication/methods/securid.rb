require 'net/ssh/prompt'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "keyboard-interactive" SSH authentication method.
        class Securid < Abstract
          include Prompt

          USERAUTH_INFO_REQUEST  = 60
          USERAUTH_INFO_RESPONSE = 61

          # Attempt to authenticate the given user for the given service.
          def authenticate(next_service, username, password=nil)
            debug { "trying SecurID two factor authentication" }
            send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))

            count = 0
            loop do
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "keyboard-interactive succeeded" }
                return true
              when USERAUTH_FAILURE
                debug { "keyboard-interactive failed" }

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'keyboard-interactive'

                return false
              when USERAUTH_INFO_REQUEST
                name = message.read_string
                instruction = message.read_string
                debug { "keyboard-interactive info request" }

                unless password
                  puts(name) unless name.empty?
                  puts(instruction) unless instruction.empty?
                end

                lang_tag = message.read_string
                responses =[]
  
                message.read_long.times do
                  text = message.read_string
                  echo = message.read_bool
                  responses << (password[count] || prompt(text, echo))
                end
                count == 1 ? password == nil : count = 1
                msg = Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, responses.length, :string, responses)
                send_message(msg)
              else
                raise Net::SSH::Exception, "unexpected reply in keyboard interactive: #{message.type} (#{message.inspect})"
              end
            end
          end
        end

      end
    end
  end
end

#ifndef XCD_HPP
#define XCD_HPP

#include <thread>
#include "xcd_protocol_handler.hpp"

void cleanUp();

class ConnectionManager
{
    private:
        PROTOCOL_VERSION connected_version = PV_NONE;
        ProgramState state;
        Parameter params;
        CTRL_FRAME ctrl_header;
        int clientSocket = 0;
        int err_state = 0;
        
        int pvIsValid(PROTOCOL_VERSION pv)
        {
            int valid = 0;

            if(pv > PV_NONE && pv < PV_LAST)
            {
                for(PROTOCOL_VERSION ver : PROTOCOL_VERSION_VEC)
                {
                    valid = pv == ver;
                    if(valid) break;
                }
            }

            return valid;
        }

        int svIsValid(SECURITY_VERSION sv)
        {
            int valid = 0;

            if(sv > SV_NONE && sv < SV_LAST)
            {
                for(SECURITY_VERSION ver : params.allowedEncryptionVec)
                {
                    valid = sv == ver;
                    if(valid) break;
                }
            }

            return valid;
        }

        // returns 1 if flags valid, 0 if not
        int validFlags(uint8_t fl)
        {
            return ( ((fl & FLAG_NEW_TRANSMISSION) == FLAG_NEW_TRANSMISSION) || ((fl & FLAG_NEW_TRANSMISSION) == FLAG_NEW_TRANSMISSION) || ((fl & FLAG_BINARY_TRANSMISSION) == FLAG_BINARY_TRANSMISSION) );
        }

        // returns 1 if header is valid, 0 if not
        int ctrlFrameValid()
        {
            int ret_value = 1;

            if(!svIsValid(ctrl_header.sv)) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd.hpp::ConnectionManager::ctrlFrameValid::Unsupported encryption method or method not allowed by whitelist." << std::endl;
                return 0;
            }

            if(!pvIsValid(ctrl_header.pv)) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd.hpp::ConnectionManager::ctrlFrameValid::Unsupported protocol version." << std::endl;
                return 0;
            }

            ret_value = ret_value && validFlags(ctrl_header.flags);
            ret_value = ret_value && ctrl_header.transmission_id > 0;

            return ret_value;
        }

        void mainLoop()
        {
            bool connected = true;
            while(connected)
            {
                switch (state)
                {
                    case STATE_RCV_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "DEBUG::ConnectionManager::reading ctrl frame" << std::endl;
                        #endif
                        
                        //reading client ctrl_frame from socket
                        int err = sio::read_from_socket(clientSocket, &ctrl_header, CTRL_FRAME_SIZE, MSG_WAITALL);
                        if(!err)
                        {
                            // memcpy(&ctrl_header, buff, CTRL_FRAME_SIZE);
                            if(ctrlFrameValid())
                            {
                                connected_version = ctrl_header.pv;
                                state = STATE_START_PROTOCOL_MANAGER;
                            }
                            else
                            {
                                state = STATE_STOP_CONNECTION_MANAGER;
                                *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::ERROR::Protocol Error, unsupported CTRL_FRAME." << std::endl;
                            }
                        }
                        else
                            state = STATE_STOP_CONNECTION_MANAGER;
                        break;                    
                    }

                    case STATE_START_PROTOCOL_MANAGER:
                    {
                        params.sv = secVersionLookupMap.at(connected_version);

                        DefaultProtocolHandler ph_default(clientSocket, params, ctrl_header);
                        if(ph_default.getError())
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::ERROR::DefaultProtocolHandler returned an error." << std::endl;
                            err_state = 1;
                        }
                        state = STATE_STOP_CONNECTION_MANAGER;
                        break;
                    }

                    case STATE_STOP_CONNECTION_MANAGER:
                    {
                        connected = false;
                        break;
                    }
                    
                    default:
                        break;
                }
            }
        }

    public:
        ConnectionManager(int sock, Parameter p)
        {
            clientSocket = sock;
            params = p;
            state = STATE_RCV_CTRL_FRAME;
            mainLoop();
        }

        ~ConnectionManager() {}
};


#endif
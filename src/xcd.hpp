#ifndef XCD_HPP
#define XCD_HPP

#include <thread>
#include <atomic>

#include "xcd_protocol_handler.hpp"


class ConnectionManager
{
    private:
        PROTOCOL_VERSION connected_version = PV_NONE; // TODO: change to SECURITY_VERSION
        ProgramState state;
        Parameter params;
        CTRL_FRAME ctrl_header;
        int clientSocket = 0;
        int err_state = 0;
        std::atomic<bool> done{false};
        std::jthread worker;
        
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

        int pvIsValid(PROTOCOL_VERSION pv)
        {
            int valid = 0;
            if(pv > PV_NONE && pv < PV_LAST) {
                for(PROTOCOL_VERSION ver : params.allowedProtocolVec) {
                    valid = pv == ver;
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
                *global_info.stderrStream << tool::current_time_string() << "::xcd.hpp::ConnectionManager::ctrlFrameValid::Unsupported protocol version or protocol not allowed by whitelist." << std::endl;
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
                        //reading client ctrl_frame from socket
                        int err = sio::read_from_socket(clientSocket, &ctrl_header, CTRL_FRAME_SIZE, MSG_WAITALL);
                        if(!err)
                        {
                            if(ctrlFrameValid())
                            {
                                connected_version = ctrl_header.pv; // TODO: change to connected_version = ctrl_header.sv
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
                        params.sv = ctrl_header.sv; // TODO: change to params.sv = connected_version

                        EncryptedProtocolHandler ph_encrypted(clientSocket, params, ctrl_header);
                        if(ph_encrypted.getError())
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
            done = true;
        }

    public:
        ConnectionManager(int sock, Parameter p)
        {
            clientSocket = sock;
            params = p;
            state = STATE_RCV_CTRL_FRAME;
            worker = std::jthread{&ConnectionManager::mainLoop, this};
        }

        ~ConnectionManager() {}

        int GetClientSocket() { return clientSocket; }

        bool isDone() { return done.load(); }
};

#endif
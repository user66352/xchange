#ifndef XCD_HPP
#define XCD_HPP

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

        // returns 1 if flags valid, 0 if not
        int validFlags(uint8_t fl)
        {
            return (fl == FLAG_NEW_TRANSMISSION) || (fl == (FLAG_NEW_TRANSMISSION | FLAG_BINARY_TRANSMISSION));
        }

        // returns 1 if header is valid, 0 if not
        int ctrlFrameValid()
        {
            int ret_value = 0;

            ret_value = pvIsValid(ctrl_header.pv);
            ret_value |= validFlags(ctrl_header.flags);
            ret_value |= ctrl_header.transmission_id > 0;

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
                        void *buff = static_cast<void *>(&ctrl_header);
                        //reading client ctrl_frame from socket
                        int err = sio::read_from_socket(clientSocket, buff, CTRL_FRAME_SIZE, MSG_WAITALL);
                        if(!err)
                        {
                            memcpy(&ctrl_header, buff, CTRL_FRAME_SIZE);
                            if(ctrlFrameValid())
                            {
                                connected_version = ctrl_header.pv;
                                state = STATE_SELECT_PROTOCOL_MANAGER;
                            }
                            else
                            {
                                state = STATE_STOP_CONNECTION_MANAGER;
                                // TODO: send reason for disconnect to client
                                *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::ERROR::Protocol Error, unsupported CTRL_FRAME." << std::endl;
                            }
                        }
                        break;                    
                    }

                    case STATE_SELECT_PROTOCOL_MANAGER:
                    {
                        switch (connected_version)
                        {
                            case PV_00_01:
                            {
                                ProtocolHandler_0001 ph_default(clientSocket, params, ctrl_header);
                                if(ph_default.getError())
                                {
                                    *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::ERROR::ProtocolHandler_ChaCha20 returned an error." << std::endl;
                                    err_state = 1;
                                }
                                state = STATE_STOP_CONNECTION_MANAGER;
                                break;
                            }

                            case PV_CHACHA20:
                            {
                                #ifdef DEBUG
                                std::cout << "DEBUG::ProtocolHandler_ChaCha20 selected" << std::endl;
                                #endif

                                if(!params.chacha20KeyFile.size())
                                {
                                    *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::WARNING::ChaCha20 Connection refused (keyFile empty)." << std::endl;
                                    state = STATE_STOP_CONNECTION_MANAGER;
                                    break;
                                }

                                ProtocolHandler_ChaCha20 ph_chacha20(clientSocket, params, ctrl_header);
                                if(ph_chacha20.getError())
                                {
                                    *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::ERROR::ProtocolHandler_ChaCha20 returned an error." << std::endl;
                                    err_state = 1;
                                }
                                state = STATE_STOP_CONNECTION_MANAGER;
                                break;
                            }

                            default:
                                break;
                        }
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
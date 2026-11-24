#ifndef XCD_PROTOCOL_HANDLER_HPP
#define XCD_PROTOCOL_HANDLER_HPP

#include "xchange.hpp"
#include "socketIO_handler.hpp"

enum ProgramState
{
    STATE_WAIT_FOR_CONNECTION,
    STATE_START_CONN_MANAGER,
    STATE_START_PROTOCOL_MANAGER,
    STATE_SELECT_PROTOCOL_MANAGER,
    STATE_STOP_PROTOCOL_MANAGER,
    STATE_STOP_CONNECTION_MANAGER,
    STATE_ACCEPT_CONNECTION,
    STATE_GET_TYPE,
    STATE_RCV_CTRL_FRAME,
    STATE_RCV_DATA,
    STATE_RCV_DATA_FRAME,
    STATE_RCV_FILENAME,
    STATE_RCV_FILE_DATA,
    STATE_SND_IV,
    STATE_FINAL_ACK,
    STATE_READ_IV,
    STATE_READ_UID,
    STATE_CHACHA20_GET_IV,
    STATE_CHACHA20_READ_KEY_FILE,
    STATE_READ_KEY_FILE,
    STATE_CM_CLOSE_CONN,
    STATE_PM_CLOSE_CONN,
    STATE_EOT,
    STATE_STOP_SERVER
};

struct Parameter
{
    std::string outDir = "";
    std::string msgOutFile = "";
    std::string logFile = "";
    std::string chacha20KeyFile = "";
    std::string encryptionWhiteList = "";
    std::string protocolWhitelist = "";
    SECURITY_VERSION sv = SV_NONE;
    std::vector<SECURITY_VERSION> allowedEncryptionVec = SECURITY_VERSION_VEC;
    std::vector<PROTOCOL_VERSION> allowedProtocolVec = PROTOCOL_VERSION_VEC;
    uint32_t ip = INADDR_ANY;
    uint16_t port = DEFAULT_PORT;
    bool help = false;
    bool version = false;
    bool PrintNewID = false;
};


// DEBUG!!!
void printEncData(SocketIO_Manager *siom)
{
    std::cout << "xcd_protocol_handler.hpp::DEBUG::SocketIO::printEncData/IV send to client:\n";
    byte *iv = siom->getEncryptionModule()->getIV();
    int iv_size = siom->getEncryptionModule()->getIVSize();
    std::cout << tool::byteToHex(iv, iv_size, 'l') << std::endl;
}


class EncryptedProtocolHandler
{
    private:
        int ClientSocket = 0;
        int err_state = 0;
        char *pln_buffer = nullptr;
        Parameter param;
        ProgramState state;
        DATA_TYPE type = TYPE_NONE;     // transfer type: message | binary/file
        CTRL_FRAME ctrl_frame;
        SocketIO_Manager *socketIO = nullptr;

        void init()
        {
            socketIO = new SocketIO_Manager(ClientSocket, param.sv, ctrl_frame.pv);
            if(socketIO->GetError()) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::init::ERROR::Could not create SocketIO_Manager." << std::endl;
                err_state = 1;
                return;
            }

            pln_buffer = socketIO->GetPlnBuffer();
            state = STATE_GET_TYPE;
        }

        void setConnectionType()
        {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;
        }

        int recv_message()
        {
            bool receiving = true;
            while(receiving)
            {
                switch (state)
                {
                    case STATE_RCV_DATA:
                    {
                        state = STATE_RCV_DATA_FRAME;
                        break;
                    }

                    case STATE_RCV_DATA_FRAME:
                    {
                        socketIO->SetFrameOrder(1); // only one frame will be received per message with order nbr 1

                        int received_byte = socketIO->ReadDataFrame();

                        if(received_byte == -1) {
                            *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::recv_message::Error::Could not read data frame." << std::endl;
                            return 1;
                        }

                        // print message to stdout target
                        pln_buffer[DATA_FRAME_HEADER_SIZE + received_byte] = 0;     // 0 terminate message string
                        const char *msg = &(pln_buffer[DATA_FRAME_HEADER_SIZE]);
                        *global_info.stdoutStream << "\n" << tool::current_time_string() << "::Message:\n";
                        *global_info.stdoutStream << msg << std::endl;

                        receiving = false; // at the moment message can not excceed MAX_DATA_BLOCK_SIZE or more than one DATA_FRAME
                        break;
                    }
                    
                    default:
                        break;
                }
            }
            return 0;
        }

        // returns the length of the filename, > 0 on success
        // -1 on failure
        int recv_filename(char *filename)
        {
            int return_code = -1;
            int recv_val = socketIO->ReadDataFrame();

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_filename::ERROR::Filename too long." << std::endl;
                return return_code;
            }

            if(recv_val > 0)
            {
                // copy filename to filename array if we read frame 0
                if((socketIO->GetFrameOrderRcvChn() - 1) == 0)
                {
                    memcpy(filename, &pln_buffer[DATA_FRAME_HEADER_SIZE], recv_val);
                    return_code = recv_val;
                }
                else
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_filename::ERROR::Could not read from frame 0." << std::endl;
            }
            else
            {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_filename::ERROR::Could not retrieve filename." << std::endl;
                return return_code;
            }
            return return_code;
        }

        // return 0 on success, 1 on failure
        int recv_file()
        {
            char filename[MAX_FILENAME_LENGTH + 1] = { 0 }; // +1 to make sure filename is zero-terminated
            int err = recv_filename(filename);
            if(err < 0)
            {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_file::ERROR::Could not get filename." << std::endl;
                return 1;
            }

            std::string path = "";
            path.append(param.outDir);
            if(path[path.size()-1] != *"/") path.append("/");
            path.append(filename);

            const std::filesystem::path filePath{path};
            if(std::filesystem::exists(filePath))
            {
                *global_info.stderrStream << "\n" << tool::current_time_string() << "::File:" << std::endl;
                *global_info.stderrStream << "File already exists: " << path << std::endl;
                return 1;
            }

            std::ofstream os(filePath, std::ofstream::binary);

            int recv_value = 0;
            bool reading = true;
            while(reading)
            {
                recv_value = socketIO->ReadDataFrame();

                if(recv_value == -1) {
                    reading = false;
                    *global_info.stderrStream << tool::current_time_string() << ":xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_file::ERROR::Could not get entire file." << std::endl;
                    recv_value = -1;
                }
                else reading = recv_value != EOT;

                if(reading)
                    os.write(&pln_buffer[DATA_FRAME_HEADER_SIZE], recv_value);
                else
                    os.close();
            }

            // EOT indicates normal end of transmission
            if(recv_value == EOT) {
                *global_info.stdoutStream << "\n" << tool::current_time_string() << "::File:\n";
                *global_info.stdoutStream << path << std::endl;
                err = 0;
            }
            else {
                // delete transfered data if incomplete
                std::filesystem::remove(filePath);
                err = 1;
            }

            return err;
        }

        void ctrl_loop()
            {
                int err = 0;
                bool connected = true;

                while(connected)
                {
                    switch (state)
                    {
                        case STATE_GET_TYPE:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_GET_TYPE" << std::endl;
                            #endif

                            setConnectionType();
                            if(type == TYPE_NONE)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Type not defined." << std::endl;
                                err = 1;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else {
                                state = STATE_READ_IV;
                                socketIO->SetTransferMode(type);
                                socketIO->SetTransmissionID(ctrl_frame.transmission_id);
                            }
                            break;
                        }

                        case STATE_READ_IV:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_READ_IV" << std::endl;
                            #endif

                            err = socketIO->SetIVFromSocket(CNL_RCV);
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not set IV for ChaCha20 Cipher." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else if(ctrl_frame.pv == PV_KPK_X25519) {
                                state = STATE_READ_UID;
                            } else {
                                state = STATE_ACCEPT_CONNECTION;
                            }
                            break;
                        }

                        case STATE_READ_UID:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_READ_UID" << std::endl;
                            #endif

                            err = socketIO->ReadUIDFromSocket();
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not set remote public key." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            } else
                                state = STATE_ACCEPT_CONNECTION;

                            break;
                        }

                        case STATE_ACCEPT_CONNECTION:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_ACCEPT_CONNECTION/send ctrl_frame & IV" << std::endl;
                            printEncData(socketIO);
                            #endif

                            err = socketIO->SendCtrlFrameEncrypted();
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not send initial ACK." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                                state = STATE_READ_KEY_FILE;
                            break;
                        }

                        case STATE_READ_KEY_FILE:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_READ_KEY_FILE" << std::endl;
                            #endif

                            switch (ctrl_frame.pv)
                            {
                                case PV_X25519:
                                    err = socketIO->PublicKeyExchange();
                                    break;

                                case PV_PSK_X25519:
                                    err = socketIO->EncReadKeyFromFile(param.chacha20KeyFile);
                                    err |= socketIO->DecReadKeyFromFile(param.chacha20KeyFile);
                                    err |= socketIO->PublicKeyExchangeAuthenticated();
                                    break;

                                case PV_KPK_X25519:
                                    err = socketIO->AuthenticatedKeyExchangeFromConfig();
                                    break;

                                default:
                                    err = 1;
                                    break;
                            }

                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not set encryption keys." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else{
                                state = STATE_RCV_DATA;
                            }
                            break;
                        }

                        case STATE_RCV_DATA:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_RCV_DATA" << std::endl;
                            #endif

                            if(type == TYPE_TXT) err = recv_message();
                            else if(type == TYPE_BIN) err = recv_file();
                            if(err) 
                            {
                                err_state = 1;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                            {
                                state = STATE_FINAL_ACK;
                            }
                            break;
                        }

                        case STATE_FINAL_ACK:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_FINAL_ACK" << std::endl;
                            #endif

                            err = socketIO->SendAck(ACK_OK, ctrl_frame.transmission_id);        // send final ACK to accknowledge successful reception
                            tool::sleep(XCD_CONFIRM_WAIT_MICROS);        // wait before closing the socket so client can read ACK without error
                            state = STATE_PM_CLOSE_CONN;
                            break;
                        }

                        case STATE_PM_CLOSE_CONN:
                        {
                            #ifdef DEBUG
                            std::cout << "xcd_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_PM_CLOSE_CONN" << std::endl;
                            #endif

                            close(ClientSocket);
                            connected = false;
                            if(err) err_state = 1;
                            break;
                        }

                        default:
                            break;
                    }
                }
            }

    public:

        EncryptedProtocolHandler(int sock, Parameter p, CTRL_FRAME cf)
        {
            ClientSocket = sock;
            param = p;
            ctrl_frame = cf;

            init();
            ctrl_loop();
        }

        ~EncryptedProtocolHandler() { delete socketIO; }

        int getError() { return err_state; }
};


#endif
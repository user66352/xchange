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
    STATE_FINAL_ACK,
    STATE_READ_IV,
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
    SECURITY_VERSION sv = SV_NONE;
    std::vector<SECURITY_VERSION> allowedEncryptionVec = SECURITY_VERSION_VEC;
    uint32_t ip = INADDR_ANY;
    uint16_t port = DEFAULT_PORT;
    bool help = false;
    bool version = false;
};


class DefaultProtocolHandler
{
    private:
        int ClientSocket = 0;
        int err_state = 0;
        bool encrypted = false;
        char *pln_buffer = nullptr;
        Parameter param;
        ProgramState state;
        DATA_TYPE type = TYPE_NONE;     // transfer type: message | binary/file
        CTRL_FRAME ctrl_frame;
        SocketIO_Manager *socketIO = nullptr;

        void init()
        {
            encrypted = (ctrl_frame.flags & FLAG_ENCRYPTED) == FLAG_ENCRYPTED;

            socketIO = new SocketIO_Manager(ClientSocket, param.sv);
            if(socketIO->GetError()) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::init::ERROR::Could not create SocketIO_Manager." << std::endl;
                err_state = 1;
                return;
            }
            socketIO->SetCtrlFrame(ctrl_frame);

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
                if((socketIO->GetFrameOrder() - 1) == 0)
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
                            setConnectionType();
                            if(type == TYPE_NONE)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Type not defined." << std::endl;
                                err = 1;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                                if(encrypted) state = STATE_READ_IV;
                                else state = STATE_ACCEPT_CONNECTION;
                            break;
                        }

                        case STATE_READ_IV:
                        {
                            err = socketIO->SetIVFromSocket();
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not set IV for ChaCha20 Cipher." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                                state = STATE_READ_KEY_FILE;
                            break;
                        }

                        case STATE_READ_KEY_FILE:
                        {
                            err = socketIO->DecReadKeyFromFile(param.chacha20KeyFile);
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not read ChaCha20 key." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                                state = STATE_ACCEPT_CONNECTION;
                            break;
                        }

                        case STATE_ACCEPT_CONNECTION:
                        {
                            err = socketIO->SendAck(ACK_OK);
                            if(err)
                            {
                                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::conn_loop::ERROR::Could not send initial ACK." << std::endl;
                                state = STATE_PM_CLOSE_CONN;
                            }
                            else
                                state = STATE_RCV_DATA;
                            break;
                        }

                        case STATE_RCV_DATA:
                        {
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
                            err = socketIO->SendAck(ACK_OK);        // send final ACK to accknowledge successful reception
                            tool::sleep(XCD_CONFIRM_WAIT_MICROS);   // wait before closing the socket so client can read ACK without error
                            state = STATE_PM_CLOSE_CONN;
                            break;
                        }

                        case STATE_PM_CLOSE_CONN:
                        {
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

        DefaultProtocolHandler(int sock, Parameter p, CTRL_FRAME cf)
        {
            ClientSocket = sock;
            param = p;
            ctrl_frame = cf;

            init();
            ctrl_loop();
        }

        ~DefaultProtocolHandler() { delete socketIO; }

        int getError() { return err_state; }
};

#endif
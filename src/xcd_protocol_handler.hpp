#ifndef XCD_PROTOCOL_HANDLER_HPP
#define XCD_PROTOCOL_HANDLER_HPP

#include <vector>

#include "xchange.hpp"
#include "crypto_handler.hpp"


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
    SECURITY_VERSION sv = SV_NONE;
    uint32_t ip = INADDR_ANY;
    uint16_t port = DEFAULT_PORT;
    bool help = false;
    bool version = false;
};


class DefaultProtocolHandler
{
    private:
        int IV_LENGTH = 0;
        int KEY_LENGTH = 0;
        int DATA_BLOCK_LENGTH = 0;
        int ClientSocket = 0;
        int err_state = 0;
        uint32_t frame_order_nbr = 0;
        bool encrypted = false;
        char rcv_buffer[MAX_DATA_FRAME_SIZE];
        char pln_buffer[MAX_DATA_FRAME_SIZE + 1];
        Parameter param;
        ProgramState state;
        DATA_TYPE type = TYPE_NONE;     // transfer type: message | binary/file
        CTRL_FRAME ctrl_frame;
        Decryption *dec = nullptr;

        void PrintDecryptionMethod() {
            std::cout << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::PrintDecryptionMethod::" << dec->getCipherName() << std::endl;
        }

        void init()
        {
            encrypted = (ctrl_frame.flags & FLAG_ENCRYPTED) == FLAG_ENCRYPTED;

            if(encrypted) {
                dec = new Decryption(param.sv);
                IV_LENGTH = dec->getIVSize();
                KEY_LENGTH = dec->getKeySize();
                DATA_BLOCK_LENGTH = dec->getDataBlockSize();
            } else {
                DATA_BLOCK_LENGTH = MAX_DATA_BLOCK_SIZE;
            }

            state = STATE_GET_TYPE;

            #ifdef DEBUG
            if(dec) PrintDecryptionMethod();
            #endif
        }

        int sendAck(ACK_ERROR_CODE err)
        {
            ACK_FRAME ack;
            ack.error = err;
            return sio::write_to_socket(ClientSocket, &ack, ACK_FRAME_SIZE);
        }

        void setConnectionType()
        {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;
        }

        // read iv from socket
        // return 0 on success, -1 on failure
        int getIVFromSocket()
        {
            int err = sio::read_from_socket(ClientSocket, rcv_buffer, IV_LENGTH, MSG_WAITALL);
            if(err)
            {
                *global_info.stderrStream << tool::current_time_string() <<"::xcd_protocol_handler.hpp::DefaultProtocolHandler::getIVFromSocket::Error::Could not read iv from socket." << std::endl;
                return err;
            }
            dec->setIV(rcv_buffer);
            return 0;
        }

        int VerifyDataFrame(DATA_FRAME_HEADER &data_header) {
            // test for correct transfer id
            if(data_header.transmission_id != ctrl_frame.transmission_id) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Transmission ID missmatch." << std::endl;
                return 1;
            }

            // test for correct frame order
            if(data_header.order_nbr != frame_order_nbr) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Frame out of order." << std::endl;
                return 1;
            }

            // test if data length fits protocol expectation
            if(data_header.data_size > DATA_BLOCK_LENGTH) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Data frame data size too large." << std::endl;
                return 1;
            }

            // test data integrity
            chksum_t ChkSum = tool::fletcher16(&pln_buffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
            if(ChkSum != data_header.chksum) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Checksum missmatch." << std::endl;
                return 1;
            }

            return 0;
        }

        // reads a data frame from socket into pln_buffer
        // returns amount of user data received on success (>0), return value does not include data_header size only the payload size
        // returns -1 on failure (return < 0)
        // returns EOT when received an EOT data frame (-2)
        // data in pln_buffer starts at [DATA_FRAME_HEADER_SIZE]
        int ReadDataFrame() {
            DATA_FRAME_HEADER data_header;

            if(encrypted) {
                // read encrypted data frame
                int err = sio::read_from_socket(ClientSocket, rcv_buffer, MAX_DATA_FRAME_SIZE, MSG_WAITALL);
                if(err) {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Error reading frame from socket." << std::endl;
                    return -1;
                }
                // decrypt data from rcv_buffer to pln_buffer
                bool verified = dec->decrypt(rcv_buffer, pln_buffer, MAX_DATA_FRAME_SIZE);
                if(!verified) {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Frame verification failed." << std::endl;
                    return -1;
                }
                // copy data_header from buffer
                memcpy(&data_header, pln_buffer, DATA_FRAME_HEADER_SIZE);
            } else {
                // read plain data frame
                // read data frame header first
                int err = sio::read_from_socket(ClientSocket, &data_header, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);
                if(err) {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Could not read data frame header." << std::endl;
                    return -1;
                }

                // read entire frame to plain buffer
                if(data_header.data_size <= MAX_DATA_BLOCK_SIZE) {
                    size_t frame_size = DATA_FRAME_HEADER_SIZE + data_header.data_size;
                    if(frame_size > MAX_DATA_FRAME_SIZE) {
                        *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Frame size too large." << std::endl;
                        return -1;
                    }
                    err = sio::read_from_socket(ClientSocket, pln_buffer, frame_size, MSG_WAITALL);
                    if(err) {
                        *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Could not read plain data frame." << std::endl;
                        return -1;
                    }
                }
            }

            int verify_err = VerifyDataFrame(data_header);
            if(verify_err) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::ReadDataFrame::Error::Frame header verification failed." << std::endl;
                return -1;
            }

            frame_order_nbr++;

            // close connection at 32bit rollover
            if(frame_order_nbr == 0) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::ReadDataFrame::Warning::Maximum frame count reached for transmission." << std::endl;
                return -1;
            }

            // test for EOT frame
            int return_value = data_header.data_size;
            if(data_header.data_size == 0) {
                if(data_header.flags & FLAG_END_OF_TRANSMISSION) return_value = EOT;
                else {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::ReadDataFrame::Error::Empty (non-EOT) frame received." << std::endl;
                    return -1;
                }
            }

            return return_value;
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
                        frame_order_nbr = 1;    // only one frame will be received per message with order nbr 1

                        int received_byte = ReadDataFrame();

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
            int recv_val = ReadDataFrame();

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::recv_filename::ERROR::Filename too long." << std::endl;
                return return_code;
            }

            if(recv_val > 0)
            {
                // copy filename to filename array if we read frame 0
                if((frame_order_nbr - 1) == 0)
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
                recv_value = ReadDataFrame();

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
                            err = getIVFromSocket();
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
                            err = dec->readKey(param.chacha20KeyFile);
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
                            err = sendAck(ACK_OK);
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
                            sendAck(ACK_OK);                        // send final ACK to accknowledge successful reception
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

        ~DefaultProtocolHandler() { delete dec; }

        int getError() { return err_state; }
};

#endif
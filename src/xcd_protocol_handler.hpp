#ifndef XCD_PROTOCOL_HANDLER_HPP
#define XCD_PROTOCOL_HANDLER_HPP

#include "xchange.hpp"
#include "chacha20_handler.hpp"
#include "xchacha20poly1305tls_handler.hpp"

enum ProgramState
{
    STATE_WAIT_FOR_CONNECTION,
    STATE_START_CONN_MANAGER,
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
    STATE_CHACHA20_GET_IV,
    STATE_CHACHA20_READ_KEY_FILE,
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
    std::string xChacha20KeyFile = "";      // TODO: needs to be implemented, right now xchacha uses the chacha key
    uint32_t ip = INADDR_ANY;
    uint16_t port = DEFAULT_PORT;
    bool help = false;
    bool version = false;
};

// default protocol, no auth, no encryption, no client ident
class ProtocolHandler_0001
{
    private:
        Parameter params;
        ProgramState state;
        CTRL_FRAME ctrl_frame;
        DATA_TYPE type = TYPE_NONE;
        char rcvBuffer[MAX_DATA_FRAME_SIZE + 1];    // +1 room for zero-termination a message
        int clientSocket = 0;
        int err_state = 0;
        uint32_t frame_order_nbr = 0;

        void setConnectionType()
        {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;
        }

        int sendAck(ACK_ERROR_CODE err)
        {
            ACK_FRAME ack;
            ack.error = err;
            return sio::write_to_socket(clientSocket, &ack, ACK_FRAME_SIZE);
        }

        // return codes:
        // >0: amount of user data put into buffer, starting at data_buffer[DATA_FRAME_HEADER_SIZE]
        // -1: general recv error
        // -2: End-Of-Transmission, no data written to buffer (EOT)
        int rcv_data_frame(int sock, char *data_buffer)
        {
            DATA_FRAME_HEADER data_header;

            // read data_header from socket queue
            int ret_value = -1; // = recv(sock, data_buffer, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);
            int error = sio::read_from_socket(clientSocket, data_buffer, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);

            // if(recv_value == DATA_FRAME_HEADER_SIZE)
            if(!error)
            {
                // copy frame header to data_header struct
                memcpy(&data_header, data_buffer, DATA_FRAME_HEADER_SIZE);

                // test for correct frame order
                if(data_header.order_nbr != frame_order_nbr)
                {
                    *global_info.stderrStream << "\n" << tool::current_time_string() << "::ProtocolHandler_0001::rcv_data_frame::ERROR::Out-Of-Order frame received." << std::endl;
                    *global_info.stderrStream << "frame_order_nbr: " << frame_order_nbr << std::endl;
                    *global_info.stderrStream << "data_header.order_nbr: " << data_header.order_nbr << std::endl;
                    return -1;
                }

                // test if data_frame is valid and contains data
                if((data_header.transmission_id == ctrl_frame.transmission_id) && (data_header.data_size > 0))
                {
                    // read the entire data frame into buffer, removing it from the queue
                    int frame_size = DATA_FRAME_HEADER_SIZE + data_header.data_size;
                    error = sio::read_from_socket(sock, data_buffer, frame_size, MSG_WAITALL);
                    if(error)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::rcv_data_frame::Error::Could not read frame from socket." << std::endl;
                        return -1;
                    }
                    
                    // test for data errors/corruption
                    uint8_t chk_sum = tool::bufferChkSum(&data_buffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
                    if(chk_sum != data_header.chksum)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::rcv_data_frame::ERROR::Checksum missmatch." << std::endl;
                        return -1;
                    }

                    // increase frame count at normal exit
                    frame_order_nbr++;
                    return data_header.data_size; // recv_value >= 0 on success; data starts at data_buffer[DATA_FRAME_HEADER_SIZE]
                }
                //test end-of-transmission
                else if ((data_header.data_size == 0) && (data_header.flags & FLAG_END_OF_TRANSMISSION))
                {
                    ret_value = EOT;
                }
                else
                    ret_value = -1;
            }
            // returns here in case of EOT or a general error condition
            return ret_value;
        }

        int recv_message()
        {
            int recv_message_err = 0;
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
                        frame_order_nbr = 1;    // only 1 frame will be received per message
                        int ret_val = rcv_data_frame(clientSocket, rcvBuffer);
                        if(ret_val > 0)
                        {
                            // print message to stdout target
                            rcvBuffer[DATA_FRAME_HEADER_SIZE + ret_val] = 0;
                            const char *msg = &(rcvBuffer[DATA_FRAME_HEADER_SIZE]);
                            *global_info.stdoutStream << "\n" << tool::current_time_string() << "::Message:\n";
                            *global_info.stdoutStream << msg << std::endl;
                        }
                        else
                        {
                            recv_message_err = 1;
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::recv_message::ERROR::No Data received." << std::endl;
                        }
                        receiving = false; // at the moment message can not excceed MAX_DATA_BLOCK_SIZE or more than one DATA_FRAME
                        break;
                    }
                    
                    default:
                        break;
                }
            }
            return recv_message_err;
        }

        // returns the length of the filename, > 0 on success
        // -1 on failure
        int recv_filename(char *filename)
        {
            int return_code = -1;
            int recv_val = rcv_data_frame(clientSocket, rcvBuffer);

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::recv_filename::ERROR::Filename too long." << std::endl;
                return return_code;
            }

            if(recv_val > 0)
            {
                // copy filename to filename array if we read frame 0
                if((frame_order_nbr - 1) == 0)
                {
                    memcpy(filename, &rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_val);
                    return_code = recv_val;
                }
                else
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::recv_filename::ERROR::Could not read from frame 0." << std::endl;
            }
            else
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::recv_filename::ERROR::Could not retrieve filename." << std::endl;
                return return_code;
            }
            return return_code;
        }

        // return EOT on success
        // any other value indicates an error
        int recv_file()
        {
            char filename[MAX_FILENAME_LENGTH + 1] = { 0 }; // +1 to make sure filename is zero-terminated
            int err = recv_filename(filename);
            if(err < 0)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::recv_file::ERROR::Could not get filename." << std::endl;
                return -1;
            }

            std::string path = "";
            path.append(params.outDir);
            if(path[path.size()-1] != *"/") path.append("/");
            path.append(filename);

            const std::filesystem::path filePath{path};
            if(std::filesystem::exists(filePath))
            {
                *global_info.stderrStream << "\n" << tool::current_time_string() << "::File:" << std::endl;
                *global_info.stderrStream << "File already exists: " << path << std::endl;
                return -1;
            }

            std::ofstream os(filePath, std::ofstream::binary);

            int recv_value = 0;
            bool reading = true;
            while(reading)
            {
                recv_value = rcv_data_frame(clientSocket, rcvBuffer);
                reading = recv_value > 0;
                if(reading)
                    os.write(&rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_value);
                else
                    os.close();
            }

            // EOT indicates normal end of transmission from rcv_data_frame
            if(recv_value == EOT)
            {
                *global_info.stdoutStream << "\n" << tool::current_time_string() << "::File:\n";
                *global_info.stdoutStream << path << std::endl;
                err = 0;
            }
            else
            {
                // delete transfered data if incomplete
                std::filesystem::remove(filePath);
                err = 1;
            }

            return err;
        }

        void conn_loop()
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
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::conn_loop::ERROR::Type not defined." << std::endl;
                            err = 1;
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
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0001::conn_loop::ERROR::Could not send initial ACK." << std::endl;
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
                        sendAck(ACK_OK);    // send final ACK to accknowledge successful reception
                        tool::sleep(XCD_CONFIRM_WAIT_MICROS);   // wait before closing the socket so client can read ACK without error
                        state = STATE_PM_CLOSE_CONN;
                        break;
                    }

                    case STATE_PM_CLOSE_CONN:
                    {
                        close(clientSocket);
                        connected = false;
                        break;
                    }
                    
                    default:
                        break;
                }
            }          
        }

    public:
        ProtocolHandler_0001(int sock, Parameter p, CTRL_FRAME cf)
        {
            clientSocket = sock;
            params = p;
            ctrl_frame = cf;
            state = STATE_GET_TYPE;
            conn_loop();
        }

        ~ProtocolHandler_0001() {}

        int getError() { return err_state; }
};


/*
 --------------------------------
 ----- XCD ChaCha20 Handler -----
 --------------------------------
*/

class ProtocolHandler_ChaCha20
{
    private:
        Parameter params;
        ProgramState state;
        ChaCha20_Decrypt dec;
        CTRL_FRAME ctrl_frame;
        DATA_TYPE type = TYPE_NONE;
        char rcvBuffer[MAX_DATA_FRAME_SIZE + 1];    // +1 room for zero-termination a message
        char encryptedBuffer[MAX_DATA_FRAME_SIZE + 1];
        int clientSocket = 0;
        int err_state = 0;
        uint32_t frame_order_nbr = 0;

        void setConnectionType()
        {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;
        }

        int sendAck(ACK_ERROR_CODE err)
        {
            ACK_FRAME ack;
            ack.error = err;
            return sio::write_to_socket(clientSocket, &ack, ACK_FRAME_SIZE);
        }

        // read iv from socket and feed it into crypto++ chacha20 obj
        // return 0 on success, -1 on failure
        int getIVFromSocket()
        {
            int err = sio::read_from_socket(clientSocket, rcvBuffer, CHACHA20_IV_LENGTH, MSG_WAITALL);
            if(err)
            {
                *global_info.stderrStream << tool::current_time_string() <<"::ProtocolHandler_ChaCha20::getIVFromSocket::ERROR::Could not read iv from socket." << std::endl;
                return err;
            }
            dec.setIV(rcvBuffer);
            return 0;
        }

        // return codes:
        // >0: amount of user data put into buffer, starting at data_buffer[DATA_FRAME_HEADER_SIZE]
        // -1: general recv error
        // -2: End-Of-Transmission, no data written to buffer (EOT)
        int rcv_data_frame(char *data_buffer)
        {
            DATA_FRAME_HEADER data_header;

            int ret_value = -1;

            // read data_header from socket queue
            // 1) read encrypted data from socket
            int error = sio::read_from_socket(clientSocket, encryptedBuffer, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);
            // 2) decrypt data header to actual recvBuffer
            dec.decryptDataFrameHeader(encryptedBuffer, data_buffer, DATA_FRAME_HEADER_SIZE);

            if(!error)
            {
                // copy frame header to data_header struct
                memcpy(&data_header, data_buffer, DATA_FRAME_HEADER_SIZE);

                // test for correct frame order
                if(data_header.order_nbr != frame_order_nbr)
                {
                    *global_info.stderrStream << "\n" << tool::current_time_string() << "::ProtocolHandler_ChaCha20::rcv_data_frame::ERROR::Out-Of-Order frame received." << std::endl;
                    *global_info.stderrStream << "frame_order_nbr: " << frame_order_nbr << std::endl;
                    *global_info.stderrStream << "data_header.order_nbr: " << data_header.order_nbr << std::endl;
                    return -1;
                }

                // test if data_frame is valid and contains data
                if((data_header.transmission_id == ctrl_frame.transmission_id) && (data_header.data_size > 0))
                {
                    // read the entire data frame into buffer, removing it from the queue
                    int frame_size = DATA_FRAME_HEADER_SIZE + data_header.data_size;
                    // error = sio::read_from_socket(sock, data_buffer, frame_size, MSG_WAITALL);
                    error = sio::read_from_socket(clientSocket, encryptedBuffer, frame_size, MSG_WAITALL);
                    dec.decrypt(encryptedBuffer, data_buffer, frame_size);
                    if(error)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::rcv_data_frame::Error::Could not read frame from socket." << std::endl;
                        return -1;
                    }
                    
                    // test for data errors/corruption
                    uint8_t chk_sum = tool::bufferChkSum(&data_buffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
                    if(chk_sum != data_header.chksum)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::rcv_data_frame::ERROR::Checksum missmatch." << std::endl;
                        return -1;
                    }

                    // increase frame count at normal exit
                    frame_order_nbr++;
                    return data_header.data_size; // recv_value >= 0 on success; data starts at data_buffer[DATA_FRAME_HEADER_SIZE]
                }
                //test end-of-transmission
                else if ((data_header.data_size == 0) && (data_header.flags & FLAG_END_OF_TRANSMISSION))
                {
                    ret_value = EOT;
                }
                else
                    ret_value = -1;
            }
            // returns here in case of EOT or a general error condition
            return ret_value;
        }

        int recv_message()
        {
            int recv_message_err = 0;
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
                        frame_order_nbr = 1;    // only 1 frame will be received per message
                        int ret_val = rcv_data_frame(rcvBuffer);
                        if(ret_val > 0)
                        {
                            // print message to stdout target
                            rcvBuffer[DATA_FRAME_HEADER_SIZE + ret_val] = 0;
                            const char *msg = &(rcvBuffer[DATA_FRAME_HEADER_SIZE]);
                            *global_info.stdoutStream << "\n" << tool::current_time_string() << "::Message:\n";
                            *global_info.stdoutStream << msg << std::endl;
                        }
                        else
                        {
                            recv_message_err = 1;
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::recv_message::ERROR::No Data received." << std::endl;
                        }
                        receiving = false; // at the moment message can not excceed MAX_DATA_BLOCK_SIZE or more than one DATA_FRAME
                        break;
                    }
                    
                    default:
                        break;
                }
            }
            return recv_message_err;
        }

        // returns the length of the filename, > 0 on success
        // -1 on failure
        int recv_filename(char *filename)
        {
            int return_code = -1;
            int recv_val = rcv_data_frame(rcvBuffer);

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::recv_filename::ERROR::Filename too long." << std::endl;
                return return_code;
            }

            if(recv_val > 0)
            {
                // copy filename to filename array if we read frame 0
                if((frame_order_nbr - 1) == 0)
                {
                    memcpy(filename, &rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_val);
                    return_code = recv_val;
                }
                else
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::recv_filename::ERROR::Could not read from frame 0." << std::endl;
            }
            else
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::recv_filename::ERROR::Could not retrieve filename." << std::endl;
                return return_code;
            }
            return return_code;
        }

        // return EOT on success
        // any other value indicates an error
        int recv_file()
        {
            char filename[MAX_FILENAME_LENGTH + 1] = { 0 }; // +1 to make sure filename is zero-terminated
            int err = recv_filename(filename);
            if(err < 0)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_0101::recv_file::ERROR::Could not get filename." << std::endl;
                return -1;
            }

            std::string path = "";
            path.append(params.outDir);
            if(path[path.size()-1] != *"/") path.append("/");
            path.append(filename);

            const std::filesystem::path filePath{path};
            if(std::filesystem::exists(filePath))
            {
                *global_info.stderrStream << "\n" << tool::current_time_string() << "::File:" << std::endl;
                *global_info.stderrStream << "File already exists: " << path << std::endl;
                return -1;
            }

            std::ofstream os(filePath, std::ofstream::binary);

            int recv_value = 0;
            bool reading = true;
            while(reading)
            {
                recv_value = rcv_data_frame(rcvBuffer);
                reading = recv_value > 0;
                if(reading)
                    os.write(&rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_value);
                else
                    os.close();
            }

            // EOT indicates normal end of transmission from rcv_data_frame
            if(recv_value == EOT)
            {
                *global_info.stdoutStream << "\n" << tool::current_time_string() << "::File:\n";
                *global_info.stdoutStream << path << std::endl;
                err = 0;
            }
            else
            {
                // delete transfered data if incomplete
                std::filesystem::remove(filePath);
                err = 1;
            }

            return err;
        }

        void conn_loop()
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
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::conn_loop::ERROR::Type not defined." << std::endl;
                            err = 1;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_CHACHA20_GET_IV;
                        break;
                    }

                    case STATE_CHACHA20_GET_IV:
                    {
                        err = getIVFromSocket();
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::conn_loop::ERROR::Could not set IV for ChaCha20 Cipher." << std::endl;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_CHACHA20_READ_KEY_FILE;
                    }

                    case STATE_CHACHA20_READ_KEY_FILE:
                    {
                        err = dec.readKey(params.chacha20KeyFile);
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::conn_loop::ERROR::Could not read ChaCha20 key." << std::endl;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_ACCEPT_CONNECTION;
                    }

                    case STATE_ACCEPT_CONNECTION:
                    {
                        err = sendAck(ACK_OK);
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_ChaCha20::conn_loop::ERROR::Could not send initial ACK." << std::endl;
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
                        close(clientSocket);
                        connected = false;
                        break;
                    }

                    default:
                        break;
                }
            }          
        }

    public:
        ProtocolHandler_ChaCha20(int sock, Parameter p, CTRL_FRAME cf)
        {
            clientSocket = sock;
            params = p;
            ctrl_frame = cf;
            state = STATE_GET_TYPE;
            conn_loop();
        }

        ~ProtocolHandler_ChaCha20() {}

        int getError() { return err_state; }
};



/*
 -----------------------------------------
 ----- XCD XChaCha20Poly1305 Handler -----
 -----------------------------------------
*/


class ProtocolHandler_XChaCha20Poly1305
{
    private:
        Parameter params;
        ProgramState state;
        XChaCha20Poly1305TLS_Decrypt dec;
        CTRL_FRAME ctrl_frame;
        DATA_TYPE type = TYPE_NONE;
        char rcvBuffer[MAX_DATA_FRAME_SIZE + 1];    // +1 room for zero-termination a message
        char encryptedBuffer[MAX_DATA_FRAME_SIZE + 1];  // TODO: should be a SecBlock
        int clientSocket = 0;
        int err_state = 0;
        uint32_t frame_order_nbr = 0;

        void setConnectionType()
        {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;
        }

        int sendAck(ACK_ERROR_CODE err)
        {
            ACK_FRAME ack;
            ack.error = err;
            return sio::write_to_socket(clientSocket, &ack, ACK_FRAME_SIZE);
        }

        // read iv from socket
        // return 0 on success, -1 on failure
        int getIVFromSocket()
        {
            int err = sio::read_from_socket(clientSocket, rcvBuffer, XCHACHA20_IV_SIZE, MSG_WAITALL);
            if(err)
            {
                *global_info.stderrStream << tool::current_time_string() <<"::ProtocolHandler_XChaCha20Poly1305::getIVFromSocket::ERROR::Could not read iv from socket." << std::endl;
                return err;
            }
            dec.setIV(rcvBuffer);
            return 0;
        }

        // return codes:
        // >0: amount of user data put into buffer, starting at data_buffer[DATA_FRAME_HEADER_SIZE]
        // -1: general recv error
        // -2: End-Of-Transmission, no data written to buffer (EOT)
        int rcv_data_frame(char *data_buffer)
        {
            DATA_FRAME_HEADER data_header;

            int ret_value = -1;

            // read data_header from socket queue
            // 1) read encrypted data frame header from socket
            int error = sio::read_from_socket(clientSocket, encryptedBuffer, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);
            if(error)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::rcv_data_frame::ERROR::read_from_socket returned an error." << std::endl;
                return ret_value;
            }

            // 2) decrypt data header to actual recvBuffer
            dec.decryptDataFrameHeader(encryptedBuffer, data_buffer, DATA_FRAME_HEADER_SIZE);

            // copy frame header to data_header struct
            memcpy(&data_header, data_buffer, DATA_FRAME_HEADER_SIZE);

            // test for correct frame order
            if(data_header.order_nbr != frame_order_nbr)
            {
                *global_info.stderrStream << "\n" << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::rcv_data_frame::ERROR::Out-Of-Order frame received." << std::endl;
                *global_info.stderrStream << "frame_order_nbr: " << frame_order_nbr << std::endl;
                *global_info.stderrStream << "data_header.order_nbr: " << data_header.order_nbr << std::endl;
                return -1;
            }
            
            // test if data_frame is valid and contains data
            if((data_header.transmission_id == ctrl_frame.transmission_id) && (data_header.data_size > 0))
            {
                // read the entire data frame including attached MAC into buffer
                int frame_size = DATA_FRAME_HEADER_SIZE + data_header.data_size + POLY1305TLS_MAC_SIZE;

                error = sio::read_from_socket(clientSocket, encryptedBuffer, frame_size, MSG_WAITALL);
                if(error)
                {
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::rcv_data_frame::Error::Could not read frame from socket." << std::endl;
                    return -1;
                }

                // decrypt data
                error = dec.decrypt(encryptedBuffer, data_buffer, frame_size);
                if(error)
                {
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::rcv_data_frame::Error::Decrypting data failed." << std::endl;
                    return -1; 
                }

                // test for data errors/corruption
                uint8_t chk_sum = tool::bufferChkSum(&data_buffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);

                if(chk_sum != data_header.chksum)
                {
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::rcv_data_frame::ERROR::Checksum missmatch." << std::endl;
                    return -1;
                }
                // increase frame count at normal exit
                frame_order_nbr++;
                return data_header.data_size; // recv_value >= 0 on success; data starts at data_buffer[DATA_FRAME_HEADER_SIZE]
            }
            //test end-of-transmission
            else if ((data_header.data_size == 0) && (data_header.flags & FLAG_END_OF_TRANSMISSION))
            {
                ret_value = EOT;
            }
            else
                ret_value = -1;

            // returns here in case of EOT or a general error condition
            return ret_value;
        }

        int recv_message()
        {
            int recv_message_err = 0;
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
                        frame_order_nbr = 1;    // only 1 frame will be received per message
                        int ret_val = rcv_data_frame(rcvBuffer);
                        if(ret_val > 0)
                        {
                            // print message to stdout target
                            rcvBuffer[DATA_FRAME_HEADER_SIZE + ret_val] = 0;
                            const char *msg = &(rcvBuffer[DATA_FRAME_HEADER_SIZE]);
                            *global_info.stdoutStream << "\n" << tool::current_time_string() << "::Message:\n";
                            *global_info.stdoutStream << msg << std::endl;
                        }
                        else
                        {
                            recv_message_err = 1;
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::recv_message::ERROR::No Data received." << std::endl;
                        }
                        receiving = false; // at the moment message can not excceed MAX_DATA_BLOCK_SIZE or more than one DATA_FRAME
                        break;
                    }
                    
                    default:
                        break;
                }
            }
            return recv_message_err;
        }

        // returns the length of the filename, > 0 on success
        // -1 on failure
        int recv_filename(char *filename)
        {
            int return_code = -1;
            int recv_val = rcv_data_frame(rcvBuffer);

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::recv_filename::ERROR::Filename too long." << std::endl;
                return return_code;
            }

            if(recv_val > 0)
            {
                // copy filename to filename array if we read frame 0
                if((frame_order_nbr - 1) == 0)
                {
                    memcpy(filename, &rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_val);
                    return_code = recv_val;
                }
                else
                    *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::recv_filename::ERROR::Could not read from frame 0." << std::endl;
            }
            else
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::recv_filename::ERROR::Could not retrieve filename." << std::endl;
                return return_code;
            }
            return return_code;
        }

        // return EOT on success
        // any other value indicates an error
        int recv_file()
        {
            char filename[MAX_FILENAME_LENGTH + 1] = { 0 }; // +1 to make sure filename is zero-terminated
            int err = recv_filename(filename);
            if(err < 0)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::recv_file::ERROR::Could not get filename." << std::endl;
                return -1;
            }

            std::string path = "";
            path.append(params.outDir);
            if(path[path.size()-1] != *"/") path.append("/");
            path.append(filename);

            const std::filesystem::path filePath{path};
            if(std::filesystem::exists(filePath))
            {
                *global_info.stderrStream << "\n" << tool::current_time_string() << "::File:" << std::endl;
                *global_info.stderrStream << "File already exists: " << path << std::endl;
                return -1;
            }

            std::ofstream os(filePath, std::ofstream::binary);

            int recv_value = 0;
            bool reading = true;
            while(reading)
            {
                recv_value = rcv_data_frame(rcvBuffer);

                reading = recv_value > 0;
                if(reading)
                    os.write(&rcvBuffer[DATA_FRAME_HEADER_SIZE], recv_value);
                else
                    os.close();
            }

            // EOT indicates normal end of transmission from rcv_data_frame
            if(recv_value == EOT)
            {
                *global_info.stdoutStream << "\n" << tool::current_time_string() << "::File:\n";
                *global_info.stdoutStream << path << std::endl;
                err = 0;
            }
            else
            {
                // delete transfered data if incomplete
                std::filesystem::remove(filePath);
                err = 1;
            }

            return err;
        }

        void conn_loop()
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
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::conn_loop::ERROR::Type not defined." << std::endl;
                            err_state = 1;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_CHACHA20_GET_IV;
                        break;
                    }

                    case STATE_CHACHA20_GET_IV:
                    {
                        err = getIVFromSocket();
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::conn_loop::ERROR::Could not set IV for XChaCha20Poly1305 Cipher." << std::endl;
                            err_state = 1;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_CHACHA20_READ_KEY_FILE;
                        break;
                    }

                    case STATE_CHACHA20_READ_KEY_FILE:
                    {
                        err = dec.readKey(params.chacha20KeyFile);
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::conn_loop::ERROR::Could not read ChaCha20 key." << std::endl;
                            err_state = 1;
                            state = STATE_PM_CLOSE_CONN;
                        }
                        else
                            state = STATE_ACCEPT_CONNECTION;
                    }

                    case STATE_ACCEPT_CONNECTION:
                    {
                        err = sendAck(ACK_OK);
                        if(err)
                        {
                            *global_info.stderrStream << tool::current_time_string() << "::ProtocolHandler_XChaCha20Poly1305::conn_loop::ERROR::Could not send initial ACK." << std::endl;
                            err_state = 1;
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
                        close(clientSocket);
                        connected = false;
                        break;
                    }

                    default:
                        break;
                }
            }          
        }

    public:
        ProtocolHandler_XChaCha20Poly1305(int sock, Parameter p, CTRL_FRAME cf)
        {
            clientSocket = sock;
            params = p;
            ctrl_frame = cf;
            state = STATE_GET_TYPE;
            conn_loop();
        }

        ~ProtocolHandler_XChaCha20Poly1305()
        {
            memset(encryptedBuffer, 0x00, MAX_DATA_FRAME_SIZE + 1);
        }

        int getError() { return err_state; }
};





#endif
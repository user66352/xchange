#ifndef SOCKETIO_HANDLER_HPP
#define SOCKETIO_HANDLER_HPP

#include "xcc.hpp"
#include "crypto_handler.hpp"

class SocketIO_Manager
{
    private:
        int error = 0;
        int ClientSocket = 0;
        int DATA_BLOCK_SIZE = 0;
        uint32_t frame_order_nbr = 0;
        bool encrypted = false;
        char ioBuffer[MAX_DATA_FRAME_SIZE];
        char plnBuffer[MAX_DATA_FRAME_SIZE + 1];
        CTRL_FRAME ctrl_frame;
        Decryption *dec = nullptr;
        Encryption *enc = nullptr;

        void init(SECURITY_VERSION sv) {
            if(sv != SV_PLAIN) {
                encrypted = true;
                dec = new Decryption(sv);
                enc = new Encryption(sv);
                int block_size_enc = enc->getDataBlockSize();
                int block_size_dec = dec->getDataBlockSize();
                if(block_size_dec == block_size_enc) DATA_BLOCK_SIZE = block_size_enc;
                else error = 1;
            } else {
                DATA_BLOCK_SIZE = MAX_DATA_BLOCK_SIZE;
            }
        }

        // return 0 on success, -1 on failure
        int SendDataBuffer(int sock, void* buffer, int length)
        {
            if(length > MAX_DATA_FRAME_SIZE)
            {
                std::cerr << "xcc_protocol_handler.hpp::sendDataBuffer::ERROR::max data frame size exceeded" << std::endl;
                return -1;
            }
            return sio::write_to_socket(sock, buffer, length);
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
            if(data_header.data_size > DATA_BLOCK_SIZE) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Data frame data size too large." << std::endl;
                return 1;
            }

            // test data integrity
            chksum_t ChkSum = tool::fletcher16(&plnBuffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
            if(ChkSum != data_header.chksum) {
                *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::DefaultProtocolHandler::VerifyDataFrame::Error::Checksum missmatch." << std::endl;
                return 1;
            }

            return 0;
        }


    public:
        SocketIO_Manager(int sock, SECURITY_VERSION sv) {
            ClientSocket = sock;
            init(sv);
        }

        ~SocketIO_Manager() {
            if(dec) delete dec;
            if(enc) delete enc;
        }

        bool isEncrypted() { return encrypted; }

        int GetError() { return error; }

        int GetDataBlockSize() { return DATA_BLOCK_SIZE; }

        char *GetPlnBuffer() { return plnBuffer; }

        void SetCtrlFrame(CTRL_FRAME cf) { ctrl_frame = cf; }

        void SetFrameOrder(int nbr) { frame_order_nbr = nbr; }

        int GetFrameOrder() { return frame_order_nbr; }

        // reads a data frame from socket into plnBuffer
        // returns amount of user data received on success (>0), return value does not include data_header size only the payload size
        // returns -1 on failure (return < 0)
        // returns EOT when received an EOT data frame (-2)
        // data in pln_buffer starts at [DATA_FRAME_HEADER_SIZE]
        int ReadDataFrame() {
            DATA_FRAME_HEADER data_header;

            if(encrypted) {
                // read encrypted data frame
                int err = sio::read_from_socket(ClientSocket, ioBuffer, MAX_DATA_FRAME_SIZE, MSG_WAITALL);
                if(err) {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Error reading frame from socket." << std::endl;
                    return -1;
                }
                // decrypt data from rcv_buffer to pln_buffer
                bool verified = dec->decrypt(ioBuffer, plnBuffer, MAX_DATA_FRAME_SIZE);
                if(!verified) {
                    *global_info.stderrStream << tool::current_time_string() << "::xcd_protocol_handler.hpp::ReadDataFrame::Error::Frame verification failed." << std::endl;
                    return -1;
                }
                // copy data_header from buffer
                memcpy(&data_header, plnBuffer, DATA_FRAME_HEADER_SIZE);
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
                    err = sio::read_from_socket(ClientSocket, plnBuffer, frame_size, MSG_WAITALL);
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

        // encrypts a data_frame if required and sends it
        int SendDataFrame(DataFrame &df) {
            int send_err = 0;
            if(encrypted) {
                // encrypt data and send
                int transmit_size = enc->encrypt(df.getTransmitBuffer(), ioBuffer, df.frameSize());
                send_err = SendDataBuffer(ClientSocket, ioBuffer, transmit_size);
            } else {
                // send as plain text
                send_err = SendDataBuffer(ClientSocket, df.getTransmitBuffer(), df.frameSize());
            }
            return send_err;
        }

        // generate ctrl_frame for encryption, appends iv to ctrl_frame
        int SendCtrlFrameEncrypted(TransferInfo info)
        {
            ControlFrame control_frame;
            int iv_size = enc->getIVSize();
            CryptoPP::byte *iv = enc->getIV();

            control_frame.setProtocolVer(info.pv);
            control_frame.setSecurityVer(info.secVer);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setFlag(FLAG_ENCRYPTED);
            control_frame.setTransmissionID(info.TransmissionID);
            if(info.mode == MODE_FILE) control_frame.setFlag(FLAG_BINARY_TRANSMISSION);

            char sendBuffer[CTRL_FRAME_SIZE + MAX_IV_SIZE];

            // ctrl_frame to send buffer
            memcpy(sendBuffer, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
            // add iv to send buffer
            memcpy(&sendBuffer[CTRL_FRAME_SIZE], iv, iv_size);

            // send CTRL FRAME
            return sio::write_to_socket(info.clientSocket, sendBuffer, CTRL_FRAME_SIZE + iv_size);
        }

        int SendCtrlFramePlain(TransferInfo info)
        {
            ControlFrame control_frame;

            control_frame.setProtocolVer(info.pv);
            control_frame.setSecurityVer(info.secVer);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setTransmissionID(info.TransmissionID);
            if(info.mode == MODE_FILE) control_frame.setFlag(FLAG_BINARY_TRANSMISSION);

            // send CTRL FRAME
            return sio::write_to_socket(info.clientSocket, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
        }

        ACK_ERROR_CODE GetAckFromSocket()
        {
            ACK_FRAME ack;
            int sock_err = sio::read_from_socket(ClientSocket, &ack, ACK_FRAME_SIZE, MSG_WAITALL);
            if(sock_err)
            {
                std::cerr << "socketIO_handler.hpp::GetAckFromSocket::ERROR::Could not read ack from socket." << std::endl;
                return ACK_GENERAL_ERR;
            } else if(strcmp(ack.ack, "ACK"))
            {
                std::cerr << "socketIO_handler.hpp::GetAckFromSocket::ERROR::malformed ack" << std::endl;
                return ACK_GENERAL_ERR;
            }
            return ack.error;
        }

        int SendAck(ACK_ERROR_CODE err)
        {
            ACK_FRAME ack;
            ack.error = err;
            return sio::write_to_socket(ClientSocket, &ack, ACK_FRAME_SIZE);
        }

        // read iv from socket and sets it on decryption module (dec)
        // return 0 on success, -1 on failure
        int SetIVFromSocket()
        {
            int err = sio::read_from_socket(ClientSocket, ioBuffer, dec->getIVSize(), MSG_WAITALL);
            if(err)
            {
                *global_info.stderrStream << tool::current_time_string() <<"::socketIO_handler.hpp::DefaultProtocolHandler::getIVFromSocket::Error::Could not read iv from socket." << std::endl;
                return err;
            }
            dec->setIV(ioBuffer);
            return 0;
        }

        int DecReadKeyFromFile(std::string filename) { return dec->readKey(filename); }

        int EncReadKeyFromFile(std::string filename) { return enc->readKey(filename); }
};

#endif

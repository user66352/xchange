#ifndef XCC_PROTOCOL_HANDLER_HPP
#define XCC_PROTOCOL_HANDLER_HPP

#include "xcc.hpp"
#include "crypto_handler.hpp"

enum ProgramState
{
    STATE_NONE,
    STATE_GET_TYPE,
    STATE_RCV_INIT_ACK,
    STATE_RCV_FINAL_ACK,
    STATE_SEND_INIT_CTRL_FRAME,
    STATE_SEND_DATA,
    STATE_SET_CHACHA20_KEY,
    STATE_STOP_CLIENT
};

ACK_ERROR_CODE getAckFromSocket(int sock);
int sendDataBuffer(int sock, void* buffer, int length);
int sendCtrlFramePlain(TransferInfo info, PROTOCOL_VERSION ver);
int sendCtrlFrameEncryption(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv, int iv_size);

class DefaultProtocolHandler
{
    private:
        TransferInfo info;
        TransferMode mode = MODE_NONE;
        ProgramState state = STATE_NONE;
        Encryption *enc = nullptr;
        bool encrypted = false;
        char snd_buffer[MAX_DATA_FRAME_SIZE];
        uint32_t frameCounter = 0;
        int clientSocket = 0;
        int error = 0;

        // encrypts a data_frame if required and sends it
        int SendDataFrame(DataFrame &df) {
            int send_err = 0;
            if(encrypted) {
                // encrypt data and send
                int transmit_size = enc->encrypt(df.getTransmitBuffer(), snd_buffer, df.frameSize());
                send_err = sendDataBuffer(clientSocket, snd_buffer, transmit_size);
            } else {
                // send as plain text
                send_err = sendDataBuffer(clientSocket, df.getTransmitBuffer(), df.frameSize());
            }
            return send_err;
        }

        // returns 0 on success and 1 on failure
        int sendText()
        {
            DataFrame data_frame;

            // TODO: test msg length to be not too long
            // sending data
            int data_size = strlen(info.msg);

            if(data_size > CHACHAPOLY_DATA_BLOCK_SIZE)
            {
                std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::sendText::Error::Message too long!" << std::endl;
                std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::sendText::Info::Message can not be longer than: " << CHACHAPOLY_DATA_BLOCK_SIZE << std::endl;
                return 1;
            }

            // first message frame has count 1
            frameCounter = 1;

            // create data frame header
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);

            // set data in data frame
            char *data_buffer = const_cast<char *>(info.msg);
            data_frame.setData(data_buffer, data_size);

            int send_err = SendDataFrame(data_frame);
            if(send_err) return 1;

            data_frame.reset();
            frameCounter++;

            // send EOT frame
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            data_frame.setData(nullptr, 0);

            // encrypt data and send EOT frame
            send_err = SendDataFrame(data_frame);

            if(send_err) return 1;

            return 0;
        }



        // returns 0 on success and 1 on failure
        int sendFile()
        {
            std::string filename = "";
            uintmax_t fileSize = 0;
            uint32_t bucket = 0;
            uint32_t framesPerBucket = 0;

            DataFrame data_frame;

            if(info.bandwidth)
            {
                bucket = 1000000 / BUCKETS_PER_SEC;    // 1000000µs per sec
                int bytesPerBucket = info.bandwidth / BUCKETS_PER_SEC;
                framesPerBucket = bytesPerBucket / MAX_DATA_FRAME_SIZE;
            }

            const char *path = info.filePath;
            filename = tool::filename_from_path(path);
            std::filesystem::path filePath = path;
            std::filesystem::path absolute_path = std::filesystem::absolute(filePath);
            fileSize = std::filesystem::file_size(absolute_path);

            // create data frame header to transfer filename
            // filename characterized by order_counter == 0 && data_size > 0 && mode binary
            frameCounter = 0;
            const char *filenamePointer = filename.c_str();
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            data_frame.setData(const_cast<char *>(filenamePointer), filename.size());

            int ret_val = 0;

            ret_val = SendDataFrame(data_frame);

            if(ret_val == -1)
            {
                std::cerr << "sendFile::Error sending Filename." << std::endl;
                return 1;
            }
            data_frame.reset();

            // start sending file data
            char inBuffer[CHACHAPOLY_DATA_BLOCK_SIZE] = { 0 };
            int bytes_read = 0;
            std::ifstream is(absolute_path, std::ifstream::binary);

            int percent = 0;
            int percent_last = -1;
            uint32_t frameBudget = framesPerBucket;
            uintmax_t progress = 0;
            auto start_time = std::chrono::high_resolution_clock::now();
            while(is.good())
            {
                is.read(inBuffer, CHACHAPOLY_DATA_BLOCK_SIZE);
                bytes_read = is.gcount();
                data_frame.setOrder(++frameCounter);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setData(inBuffer, bytes_read);

                // send data frame
                ret_val = SendDataFrame(data_frame);
                if(ret_val)
                {
                    std::cerr << "sendFile::Error sending file." << std::endl;
                    is.close();
                    return 1;
                }
                data_frame.reset();

                // print progress
                progress += bytes_read;
                if(info.stats)
                {
                    percent = (( static_cast<double>(progress) / static_cast<double>(fileSize)) * 100.0);
                    if(percent > percent_last)
                    {
                        std::cout << "\rProgress: " << percent << "%";
                        std::cout.flush();
                    }
                    percent_last = percent;
                }

                // throttle bandwidth
                if(framesPerBucket)
                {
                    if(!(frameBudget--))
                    {
                        auto stop_time = std::chrono::high_resolution_clock::now();
                        auto duration = duration_cast<std::chrono::microseconds>(stop_time - start_time);
                        if(duration.count() < bucket) tool::sleep(bucket - duration.count());
                        start_time = std::chrono::high_resolution_clock::now();
                        frameBudget = framesPerBucket;
                    }
                }
            }
            is.close();

            if(progress != fileSize)
            {
                std::cerr << "sendFile::Error reading/sending entire file." << std::endl;
                return 1;
            }

            if(info.stats)
                std::cout << "\nTransfered Bytes: " << progress << "\n";

            // send end-of-transmission frame
            data_frame.reset();
            data_frame.setOrder(++frameCounter);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setData(nullptr, 0);

            // send final EOT frame
            ret_val = SendDataFrame(data_frame);
            if(ret_val)
            {
                std::cerr << "sendFile::Error closing file transfer." << std::endl;
                return 1;
            }

            return 0;
        }

        void ctrl_loop()
        {
            int err = 0;
            bool running = true;

            while(running)
            {
                switch (state)
                {
                    case STATE_GET_TYPE:
                    {
                        mode = info.mode;
                        if(mode == MODE_NONE)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Could not set transfer mode." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            if(encrypted)
                                state = STATE_SET_CHACHA20_KEY;
                            else
                                state = STATE_SEND_INIT_CTRL_FRAME;
                        break;
                    }

                    case STATE_SET_CHACHA20_KEY:
                    {
                        err = enc->readKey(info.keyFile);
                        if(err)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Error reading key file." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_INIT_CTRL_FRAME;
                        break;
                    }

                    case STATE_SEND_INIT_CTRL_FRAME:
                    {
                        if(encrypted)
                            err = sendCtrlFrameEncryption(info, info.pv, enc->getIV(), enc->getIVSize());
                        else
                            err = sendCtrlFramePlain(info, info.pv);
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_ChaCha20::ERROR::Could not send ctrl frame." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_RCV_INIT_ACK;
                        break;
                    }

                    case STATE_RCV_INIT_ACK:
                    {
                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_ChaCha20::ERROR::Initial ack error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_DATA;
                        break;
                    }

                    case STATE_SEND_DATA:
                    {
                        if(mode == MODE_FILE)
                        {
                            err = sendFile();
                        }
                        else if(mode == MODE_TEXT)
                        {
                            err = sendText();
                        }
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_ChaCha20::ERROR::Send data returned an error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        state = STATE_RCV_FINAL_ACK;                        
                        break;
                    }

                    case STATE_RCV_FINAL_ACK:
                    {
                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_ChaCha20::ERROR::Final ack error." << std::endl;
                            
                        }
                        state = STATE_STOP_CLIENT;
                    }

                    case STATE_STOP_CLIENT:
                    {
                        running = false;
                        break;
                    }

                    default:
                        break;
                }
            }
        }

    public:
        DefaultProtocolHandler(TransferInfo i) {

            info = i;
            clientSocket = info.clientSocket;
            encrypted = info.secVer != SV_PLAIN;

            if(encrypted)
                enc = new Encryption(info.secVer);
            state = STATE_GET_TYPE;
            ctrl_loop();
        }

        ~DefaultProtocolHandler() { delete enc; }

        int getErrState() { return error; }
};


/*
 ----------------------------
 ----- Shared Functions -----
 ----------------------------
*/

// read ack from socket
// return ack_status (ACK_OK on success)
ACK_ERROR_CODE getAckFromSocket(int sock)
{
    ACK_FRAME ack;
    int sock_err = sio::read_from_socket(sock, &ack, ACK_FRAME_SIZE, MSG_WAITALL);
    if(sock_err)
    {
        std::cerr << "getAckFromSocket::ERROR::Could not read ack from socket." << std::endl;
        return ACK_GENERAL_ERR;
    } else if(strcmp(ack.ack, "ACK"))
    {
        std::cerr << "getAckFromSocket::ERROR::malformed ack" << std::endl;
        return ACK_GENERAL_ERR;
    }
    return ack.error;
}

int sendCtrlFramePlain(TransferInfo info, PROTOCOL_VERSION ver)
{
    ControlFrame control_frame;

    // create CTRL Frame
    switch (info.mode)
    {
        case MODE_FILE:
        {
            control_frame.setProtocolVer(ver);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setFlag(FLAG_BINARY_TRANSMISSION);
            control_frame.setTransmissionID(info.TransmissionID);
            break;
        }

        case MODE_TEXT:
        {
            control_frame.setProtocolVer(ver);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setTransmissionID(info.TransmissionID);
            break;
        }

        default:
            break;
    }

    // send CTRL FRAME
    // TODO: serialize control_frame into a send buffer before calling write_to_socket()
    return sio::write_to_socket(info.clientSocket, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
}

// generate ctrl_frame for chacha20 encryption, appends iv to ctrl_frame
int sendCtrlFrameEncryption(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv, int iv_size)
{
    ControlFrame control_frame;

    // create CTRL Frame
    switch (info.mode)
    {
        case MODE_FILE:
        {
            control_frame.setProtocolVer(ver);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setFlag(FLAG_BINARY_TRANSMISSION);
            control_frame.setFlag(FLAG_ENCRYPTED);
            control_frame.setTransmissionID(info.TransmissionID);
            break;
        }

        case MODE_TEXT:
        {
            control_frame.setProtocolVer(ver);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION);
            control_frame.setFlag(FLAG_ENCRYPTED);
            control_frame.setTransmissionID(info.TransmissionID);
            break;
        }

        default:
            break;
    }

    char sendBuffer[CTRL_FRAME_SIZE + MAX_IV_SIZE];
    // ctrl_frame to send buffer
    memcpy(sendBuffer, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
    // add iv to send buffer
    memcpy(&sendBuffer[CTRL_FRAME_SIZE], iv, iv_size);

    // send CTRL FRAME
    return sio::write_to_socket(info.clientSocket, sendBuffer, CTRL_FRAME_SIZE + iv_size);
}

// return 0 on success, -1 on failure
int sendDataBuffer(int sock, void* buffer, int length)
{
    if(length > MAX_DATA_FRAME_SIZE)
    {
        std::cerr << "xcc_protocol_handler.hpp::sendDataBuffer::ERROR::max data frame size exceeded" << std::endl;
        return -1;
    }
    return sio::write_to_socket(sock, buffer, length);
}

#endif
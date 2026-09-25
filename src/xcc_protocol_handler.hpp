#ifndef XCC_PROTOCOL_HANDLER_HPP
#define XCC_PROTOCOL_HANDLER_HPP

#include "xcc.hpp"
#include "chacha20_handler.hpp"
#include "xchacha20poly1305tls_handler.hpp"

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
int sendDataFrame(int sock, DataFrame &df);
int sendDataBuffer(int sock, void* buffer, int length);
int sendCtrlFrame(TransferInfo info, PROTOCOL_VERSION ver);
int sendCtrlFrameChaCha20(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv);
int sendCtrlFrameXChaCha20Poly1305(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv);


class ProtocolHandler_0001
{
    private:
        PROTOCOL_VERSION pv_ver = PV_00_01;
        TransferInfo info;
        TransferMode mode = MODE_NONE;
        ProgramState state = STATE_NONE;
        uint32_t frameCounter = 0;
        int clientSocket = 0;
        int error = 0;

        // returns 0 on success and 1 on failure
        int sendText()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_0001::Info::entering sendText()" << std::endl;
            #endif

            DataFrame data_frame;

            // TODO: test msg length to be not too long
            // sending data
            int data_size = strlen(info.msg);

            // first message frame has count 1
            frameCounter = 1;

            // create data frame header
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            char *data_buffer = const_cast<char *>(info.msg);
            data_frame.setData(data_buffer, data_size);

            // send text message
            // int send_err = sio::write_to_socket(clientSocket, data_frame.getTransmitBuffer(), data_frame.frameSize());
            int send_err = sendDataFrame(clientSocket, data_frame);
            if(send_err) return 1;

            data_frame.reset();
            frameCounter++;

            // send EOT frame
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            data_frame.setData(nullptr, 0);

            // send_err = sio::write_to_socket(clientSocket, data_frame.getTransmitBuffer(), data_frame.frameSize());
            send_err = sendDataFrame(clientSocket, data_frame);
            if(send_err) return 1;

            return 0;
        }

        // returns 0 on success and 1 on failure
        int sendFile()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_0001::Info::entering sendFile()" << std::endl;
            #endif

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

            // send filename in data frame 0
            // int ret_val = sio::write_to_socket(sock, data_frame->getTransmitBuffer(), data_frame->frameSize());
            int ret_val = sendDataFrame(clientSocket, data_frame);
            if(ret_val == -1)
            {
                std::cerr << "sendFile::Error sending Filename." << std::endl;
                return 1;
            }
            data_frame.reset();

            // start sending file data
            char inBuffer[MAX_DATA_BLOCK_SIZE] = { 0 };
            int bytes_read = 0;
            // int send_bytes = 0;
            std::ifstream is(absolute_path, std::ifstream::binary);

            int percent = 0;
            int percent_last = -1;
            uint32_t frameBudget = framesPerBucket;
            uintmax_t progress = 0;
            auto start_time = std::chrono::high_resolution_clock::now();
            while(is.good())
            {
                is.read(inBuffer, MAX_DATA_BLOCK_SIZE);
                bytes_read = is.gcount();
                data_frame.setOrder(++frameCounter);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setData(inBuffer, bytes_read);

                // send data frame
                ret_val  = sendDataFrame(clientSocket, data_frame);
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
                    percent = (( (double) progress / (double) fileSize) * 100.0);
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
                    if(!(--frameBudget))
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
            // data_frame.reset();

            if(progress != fileSize)
            {
                std::cerr << "sendFile::Error reading/sending entire file." << std::endl;
                return 1;
            }

            if(info.stats)
                std::cout << "\nTransfered Bytes: " << progress << "\n";

            // send end-of-transmission frame
            data_frame.setOrder(++frameCounter);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setData(nullptr, 0);

            ret_val = sendDataFrame(clientSocket, data_frame);
            if(ret_val)
            {
                std::cerr << "sendFile::Error closing file transfer." << std::endl;
                return 1;
            }

            return 0;
        }

        void main_loop()
        {
            int err = 0;
            bool running = true;

            while(running)
            {
                switch (state)
                {
                    case STATE_GET_TYPE:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_GET_TYPE" << std::endl;
                        #endif

                        mode = info.mode;
                        if(mode == MODE_NONE)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_0001::ERROR::Could not set transfer mode." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_INIT_CTRL_FRAME;
                        break;
                    }

                    case STATE_SEND_INIT_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_INIT_CTRL_FRAME" << std::endl;
                        #endif

                        err = sendCtrlFrame(info, pv_ver);
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_0001::ERROR::Could not send ctrl frame." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_RCV_INIT_ACK;
                        break;
                    }

                    case STATE_RCV_INIT_ACK:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_INIT_ACK" << std::endl;
                        #endif

                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_0001::ERROR::Initial ack error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_DATA;
                        break;
                    }

                    case STATE_SEND_DATA:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_DATA" << std::endl;
                        #endif

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
                            std::cerr << "ProtocolHandler_0001::ERROR::Send data returned an error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        state = STATE_RCV_FINAL_ACK;                        
                        break;
                    }

                    case STATE_RCV_FINAL_ACK:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_FINAL_ACK" << std::endl;
                        #endif

                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_0001::ERROR::Final ack error." << std::endl;
                            
                        }
                        state = STATE_STOP_CLIENT;
                    }

                    case STATE_STOP_CLIENT:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_STOP_CLIENT" << std::endl;
                        #endif

                        running = false;
                        break;
                    }

                    default:
                        break;
                }
            }
        }

    public:
        ProtocolHandler_0001(TransferInfo i)
        {
            #ifdef DEBUG
            std::cout << "starting ProtocolHandler_0001" << std::endl;
            #endif
            info = i;
            clientSocket = info.clientSocket;
            state = STATE_GET_TYPE;
            main_loop();
        }

        int getErrState() { return error; }
};


// send data CHACHA20 encrypted
class ProtocolHandler_ChaCha20
{
    private:
        PROTOCOL_VERSION pv_ver = PV_CHACHA20;
        TransferInfo info;
        TransferMode mode = MODE_NONE;
        ProgramState state = STATE_NONE;
        ChaCha20_Encrypt enc;
        char encryptedBuffer[MAX_DATA_FRAME_SIZE];
        uint32_t frameCounter = 0;
        int clientSocket = 0;
        int error = 0;

        // returns 0 on success and 1 on failure
        int sendText()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_ChaCha20::Info::entering sendText()" << std::endl;
            #endif

            DataFrame data_frame;

            // TODO: test msg length to be not too long
            // sending data
            int data_size = strlen(info.msg);

            // first message frame has count 1
            frameCounter = 1;

            // create data frame header
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);

            // set data in data frame
            char *data_buffer = const_cast<char *>(info.msg);
            data_frame.setData(data_buffer, data_size);

            // encrypt data and send
            enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
            int send_err = sendDataBuffer(clientSocket, encryptedBuffer, data_frame.frameSize());
            if(send_err) return 1;

            data_frame.reset();
            frameCounter++;

            // send EOT frame
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            data_frame.setData(nullptr, 0);

            // encrypt data and send EOT frame
            enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
            send_err = sendDataBuffer(clientSocket, encryptedBuffer, data_frame.frameSize());
            if(send_err) return 1;

            return 0;
        }

        // returns 0 on success and 1 on failure
        int sendFile()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_ChaCha20::Info::entering sendFile()" << std::endl;
            #endif

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

            // send filename in data frame 0
            enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
            int ret_val = sendDataBuffer(clientSocket, encryptedBuffer, data_frame.frameSize());

            if(ret_val == -1)
            {
                std::cerr << "sendFile::Error sending Filename." << std::endl;
                return 1;
            }
            data_frame.reset();

            // start sending file data
            char inBuffer[MAX_DATA_BLOCK_SIZE] = { 0 };
            int bytes_read = 0;
            std::ifstream is(absolute_path, std::ifstream::binary);

            int percent = 0;
            int percent_last = -1;
            uint32_t frameBudget = framesPerBucket;
            uintmax_t progress = 0;
            auto start_time = std::chrono::high_resolution_clock::now();
            while(is.good())
            {
                is.read(inBuffer, MAX_DATA_BLOCK_SIZE);
                bytes_read = is.gcount();
                data_frame.setOrder(++frameCounter);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setData(inBuffer, bytes_read);

                // send data frame
                enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
                ret_val = sendDataBuffer(clientSocket, encryptedBuffer, data_frame.frameSize());
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

            enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
            ret_val = sendDataBuffer(clientSocket, encryptedBuffer, data_frame.frameSize());
            if(ret_val)
            {
                std::cerr << "sendFile::Error closing file transfer." << std::endl;
                return 1;
            }

            return 0;
        }

        void main_loop()
        {
            int err = 0;
            bool running = true;

            while(running)
            {
                switch (state)
                {
                    case STATE_GET_TYPE:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_GET_TYPE" << std::endl;
                        #endif

                        mode = info.mode;
                        if(mode == MODE_NONE)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler__ChaCha20::ERROR::Could not set transfer mode." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SET_CHACHA20_KEY;
                        break;
                    }

                    case STATE_SET_CHACHA20_KEY:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SET_CHACHA20_KEY" << std::endl;
                        #endif

                        err = enc.readKey(info.keyFile);
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_ChaCha20::ERROR::Error reading key file." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_INIT_CTRL_FRAME;
                        break;
                    }

                    case STATE_SEND_INIT_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_INIT_CTRL_FRAME" << std::endl;
                        #endif

                        err = sendCtrlFrameChaCha20(info, pv_ver, enc.getIV());
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
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_INIT_ACK" << std::endl;
                        #endif

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
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_DATA" << std::endl;
                        #endif

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
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_FINAL_ACK" << std::endl;
                        #endif

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
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_STOP_CLIENT" << std::endl;
                        #endif

                        running = false;
                        break;
                    }

                    default:
                        break;
                }
            }
        }

    public:
        ProtocolHandler_ChaCha20(TransferInfo i)
        {
            #ifdef DEBUG
            std::cout << "starting ProtocolHandler_ChaCha20" << std::endl;
            #endif
            info = i;
            clientSocket = info.clientSocket;
            state = STATE_GET_TYPE;
            main_loop();
        }

        int getErrState() { return error; }
};



// send data XCHACHA20_POLY1305TLS encrypted
class ProtocolHandler_XChaCha20Poly1305TLS
{
    private:
        PROTOCOL_VERSION pv_ver = PV_XCHACHA20POLY;
        TransferInfo info;
        TransferMode mode = MODE_NONE;
        ProgramState state = STATE_NONE;
        XChaCha20Poly1305TLS_Encrypt enc;
        char encryptedBuffer[MAX_DATA_FRAME_SIZE];
        uint32_t frameCounter = 0;
        int clientSocket = 0;
        int error = 0;

        // returns 0 on success and 1 on failure
        int sendText()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::entering sendText()" << std::endl;
            #endif

            DataFrame data_frame;

            int data_size = strlen(info.msg);

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::data_size: " << data_size << std::endl;
            #endif

            // max data size per frame reduced due to attached MAC
            // check if message size is smaller then MAX_DATA_BLOCK_SIZE - POLY1305TLS_MAC_SIZE
            int max_msg_length = MAX_DATA_BLOCK_SIZE - POLY1305TLS_MAC_SIZE;
            if(data_size > max_msg_length)
            {
                std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::Error::In XCHACHA20_POLY1305TLS mode max message length can not exceed " << max_msg_length << " byte." << std::endl;
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

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::data_frame.frameSize(): " << data_frame.frameSize() << std::endl;
            #endif

            // encrypt data and send
            int transfer_size = enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::sendText::data transfer_size: " << transfer_size << std::endl;
            #endif

            int send_err = sendDataBuffer(clientSocket, encryptedBuffer, transfer_size);
            if(send_err) return 1;

            data_frame.reset();
            frameCounter++;

            // send EOT frame
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setOrder(frameCounter);
            data_frame.setData(nullptr, 0);

            // encrypt data and send EOT frame
            transfer_size = enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::sendText::data transfer_size: " << transfer_size << std::endl;
            #endif

            send_err = sendDataBuffer(clientSocket, encryptedBuffer, transfer_size);
            if(send_err) return 1;

            return 0;
        }

        // returns 0 on success and 1 on failure
        int sendFile()
        {
            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::entering sendFile()" << std::endl;
            #endif

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

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::sending filename" << std::endl;
            #endif

            // send filename in data frame 0
            int frame_size = enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
            if(!frame_size)
            {
                std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error::Encryption of filename failed." << std::endl;
                return 1;
            }
            int ret_val = sendDataBuffer(clientSocket, encryptedBuffer, frame_size);

            if(ret_val == -1)
            {
                std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error sending Filename." << std::endl;
                return 1;
            }
            data_frame.reset();

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::Info::start sending file data" << std::endl;
            #endif

            // start sending file data
            char inBuffer[MAX_DATA_BLOCK_SIZE] = { 0 };
            int bytes_read = 0;
            std::ifstream is(absolute_path, std::ifstream::binary);

            int percent = 0;
            int percent_last = -1;
            uint32_t frameBudget = framesPerBucket;
            uintmax_t progress = 0;
            auto start_time = std::chrono::high_resolution_clock::now();
            while(is.good())
            {
                is.read(inBuffer, MAX_DATA_BYTE_PER_FRAME_XPOLY);
                bytes_read = is.gcount();
                data_frame.setOrder(++frameCounter);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setData(inBuffer, bytes_read);

                // send data frame
                frame_size = enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());
                if(!frame_size)
                {
                    std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error::Encryption of file data failed." << std::endl;
                    goto return_error;
                }
                ret_val = sendDataBuffer(clientSocket, encryptedBuffer, frame_size);
                if(ret_val)
                {
                    std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error::Failure sending file." << std::endl;
                    goto return_error;
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

            // test if all required bytes got transfered
            if(progress != fileSize)
            {
                std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error reading/sending entire file." << std::endl;
                return 1;
            }

            if(info.stats)
                std::cout << "\nTransfered Bytes: " << progress << "\n";

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::preparing EOF frame!" << std::endl;
            #endif

            // send end-of-transmission frame
            data_frame.reset();
            data_frame.setOrder(++frameCounter);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setData(nullptr, 0);

            frame_size = enc.encrypt(data_frame.getTransmitBuffer(), encryptedBuffer, data_frame.frameSize());

            #ifdef DEBUG
            std::cout << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::EOF frame size: " << frame_size  << std::endl;
            #endif

            ret_val = sendDataBuffer(clientSocket, encryptedBuffer, frame_size);
            if(ret_val)
            {
                std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::sendFile::Error closing file transfer." << std::endl;
                return 1;
            }

            return 0;

            return_error:
                is.close();
                return 1;
        }

        void main_loop()
        {
            int err = 0;
            bool running = true;

            while(running)
            {
                switch (state)
                {
                    case STATE_GET_TYPE:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_GET_TYPE" << std::endl;
                        #endif

                        mode = info.mode;
                        if(mode == MODE_NONE)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Could not set transfer mode." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SET_CHACHA20_KEY;
                        break;
                    }

                    case STATE_SET_CHACHA20_KEY:
                    {
                        err = enc.readKey(info.keyFile);
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Error reading key file." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_INIT_CTRL_FRAME;
                        break;
                    }

                    case STATE_SEND_INIT_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_INIT_CTRL_FRAME" << std::endl;
                        #endif

                        err = sendCtrlFrameXChaCha20Poly1305(info, pv_ver, enc.getIV());
                        if(err)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Could not send ctrl frame." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_RCV_INIT_ACK;
                        break;
                    }

                    case STATE_RCV_INIT_ACK:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_INIT_ACK" << std::endl;
                        #endif

                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Initial ack error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_DATA;
                        break;
                    }

                    case STATE_SEND_DATA:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_SEND_DATA" << std::endl;
                        #endif

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
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Send data returned an error." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        state = STATE_RCV_FINAL_ACK;                        
                        break;
                    }

                    case STATE_RCV_FINAL_ACK:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_RCV_FINAL_ACK" << std::endl;
                        #endif

                        ACK_ERROR_CODE ackErr = getAckFromSocket(clientSocket);
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "ProtocolHandler_XChaCha20Poly1305TLS::ERROR::Final ack error." << std::endl;
                            
                        }
                        state = STATE_STOP_CLIENT;
                    }

                    case STATE_STOP_CLIENT:
                    {
                        #ifdef DEBUG
                        std::cout << "PH STATE: STATE_STOP_CLIENT" << std::endl;
                        #endif

                        running = false;
                        break;
                    }

                    default:
                        break;
                }
            }
        }

    public:
        ProtocolHandler_XChaCha20Poly1305TLS(TransferInfo i)
        {
            #ifdef DEBUG
            std::cout << "starting ProtocolHandler_XChaCha20Poly1305" << std::endl;
            #endif
            info = i;
            clientSocket = info.clientSocket;
            state = STATE_GET_TYPE;
            main_loop();
        }

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

int sendCtrlFrame(TransferInfo info, PROTOCOL_VERSION ver)
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
int sendCtrlFrameChaCha20(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv)
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

    char sendBuffer[CTRL_FRAME_SIZE + CHACHA20_IV_LENGTH];
    memcpy(sendBuffer, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
    memcpy(&sendBuffer[CTRL_FRAME_SIZE], iv, CHACHA20_IV_LENGTH);

    // send CTRL FRAME
    return sio::write_to_socket(info.clientSocket, sendBuffer, CTRL_FRAME_SIZE + CHACHA20_IV_LENGTH);
}

// generate ctrl_frame for xchacha20poly1305 encryption, appends iv to ctrl_frame
int sendCtrlFrameXChaCha20Poly1305(TransferInfo info, PROTOCOL_VERSION ver, CryptoPP::byte *iv)
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

    char sendBuffer[CTRL_FRAME_SIZE + XCHACHA20_IV_SIZE];
    memcpy(sendBuffer, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
    memcpy(&sendBuffer[CTRL_FRAME_SIZE], iv, XCHACHA20_IV_SIZE);

    // send CTRL FRAME
    return sio::write_to_socket(info.clientSocket, sendBuffer, CTRL_FRAME_SIZE + XCHACHA20_IV_SIZE);
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

// return 0 on success, -1 on failure
int sendDataFrame(int sock, DataFrame &df)
{
    if(df.frameSize() > MAX_DATA_FRAME_SIZE)
    {
        std::cerr << "xcc_protocol_handler.hpp::sendDataFrame::ERROR::max data frame size exceeded" << std::endl;
        return -1;
    }
    return sio::write_to_socket(sock, df.getTransmitBuffer(), df.frameSize());
}

#endif
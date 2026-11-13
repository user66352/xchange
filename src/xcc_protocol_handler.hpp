#ifndef XCC_PROTOCOL_HANDLER_HPP
#define XCC_PROTOCOL_HANDLER_HPP

#include "socketIO_handler.hpp"

enum ProgramState
{
    STATE_NONE,
    STATE_GET_TYPE,
    STATE_RCV_INIT_ACK,
    STATE_RCV_SRV_CTRL_FRAME,
    STATE_RCV_SRV_IV,
    STATE_RCV_FINAL_ACK,
    STATE_SEND_INIT_CTRL_FRAME,
    STATE_SEND_DATA,
    STATE_SET_INITIAL_KEY,
    STATE_STOP_CLIENT
};


struct FileInfo
{
    std::string filename = "";
    bool stdi = false;
};

namespace eph {

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
        return ( ((fl & FLAG_NEW_TRANSMISSION) == FLAG_NEW_TRANSMISSION) || ((fl & FLAG_NEW_TRANSMISSION) == FLAG_NEW_TRANSMISSION) || ((fl & FLAG_BINARY_TRANSMISSION) == FLAG_BINARY_TRANSMISSION) );
    }

    // returns 1 if header is valid, 0 if not
    int ctrlFrameValid(CTRL_FRAME &ctrl_frame)
    {
        int ret_value = 1;

        if(!pvIsValid(ctrl_frame.pv)) {
            *global_info.stderrStream << tool::current_time_string() << "::xcd.hpp::ConnectionManager::ctrlFrameValid::Unsupported protocol version." << std::endl;
            return 0;
        }

        ret_value = ret_value && validFlags(ctrl_frame.flags);
        ret_value = ret_value && ctrl_frame.transmission_id > 0;

        return ret_value;
    }

    int RcvServerCtrlFrame(int sock, CTRL_FRAME &ctrl_frame)
    {
        //reading server ctrl_frame from socket
        int err = sio::read_from_socket(sock, &ctrl_frame, CTRL_FRAME_SIZE, MSG_WAITALL);
        if(!err) err = !(ctrlFrameValid(ctrl_frame));
        return err;
    }

}


// manage read from stdin or file
class FileIO
{
    private:
        std::istream *is = nullptr;
        std::string filename = "";
        bool stdi = false;
        int error = 0;

        void init() {
            
            if(stdi) {
                is = &std::cin;
            }
            else {
                std::filesystem::path absolute_path = std::filesystem::absolute(filename);
                filename = tool::filename_from_path(absolute_path.c_str());
                is = new std::ifstream(absolute_path, std::ifstream::binary);
            }
            
            if(is->fail()) {
                *global_info.stderrStream << tool::current_time_string() <<"::xcd_protocol_handler.hpp::FileIO::init::Error::Could not open source file." << std::endl;
                error = 1;
            }
        }

    public:
        FileIO(FileInfo fi) {
            stdi = fi.stdi;
            filename = fi.filename;
            init();
        }

        ~FileIO() {
            if(is != &std::cin) {
                std::ifstream *ifs = dynamic_cast<std::ifstream *>(is);
                ifs->close();
            }
        }

        // read size bytes to buffer
        // returns amount of bytes read; return EOT at end of file or -1 on failure
        int ReadBytes(void *buffer, int size) {
            char *ioBuffer = static_cast<char *>(buffer);

            if(is->good()) {
                is->read(ioBuffer, size);
                return is->gcount();
            }
            else if(is->eof()) {
                return EOT;
            }

            error = 1;
            return -1;
        }

        std::string GetFilename() {
            return filename;
        }

        bool isGood() { return is->good(); }

        bool isEOF() { return is->eof(); }

        int ErrorState() { return error; }
};


class EncryptedProtocolHandler
{
    private:
        TransferInfo info;
        DATA_TYPE dtype = TYPE_NONE;
        ProgramState state = STATE_NONE;
        FileIO *file_io = nullptr;
        SocketIO_Manager *socketIO = nullptr;
        int DATA_BLOCK_SIZE = 0;
        int clientSocket = 0;
        int error = 0;

        // read message from stdin
        std::string ReadMessage() {

            std::string msg = "";
            char strBuffer[MAX_DATA_BLOCK_SIZE + 1];

            FileInfo file_info;
            file_info.stdi = info.read_stdin;

            if(info.dtype == TYPE_BIN) {
                file_info.filename = info.filePath;
            }

            file_io = new FileIO(file_info);
            int ret_value = file_io->ReadBytes(strBuffer, DATA_BLOCK_SIZE);
            if(ret_value == -1) {
                std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ReadMessage::Error::Could not read message." << std::endl;
                return msg;
            }

            strBuffer[ret_value] = 0;
            msg = strBuffer;

            return msg;
        }

        // returns 0 on success and 1 on failure
        int sendMessage()
        {

            std::string message = "";
            DataFrame data_frame;

            if(info.read_stdin) {
                message = ReadMessage();
                if(!message.size()) {
                    std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::sendMessage::Error::Could not read message from stdin." << std::endl;
                    return 1;
                }
            } else {
                message = info.msg;
            }
            
            int data_size = message.size();

            if(data_size > DATA_BLOCK_SIZE)
            {
                std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::sendMessage::Error::Message too long!" << std::endl;
                std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::sendMessage::Info::Message can not be longer than: " << DATA_BLOCK_SIZE << std::endl;
                return 1;
            }

            // sending data
            // first message frame has count 1 to not confuse it with frame 0 that is used for filename in file mode
            socketIO->SetFrameOrder(1);

            // create data frame header
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);

            // set data in data frame
            char *data_buffer = const_cast<char *>(message.c_str());
            data_frame.setData(data_buffer, data_size);

            int send_err = socketIO->SendDataFrame(data_frame);
            if(send_err) return 1;

            data_frame.reset();

            // send EOT frame
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setData(nullptr, 0);

            // encrypt data and send EOT frame
            send_err = socketIO->SendDataFrame(data_frame);

            if(send_err) return 1;

            return 0;
        }

        // returns 0 on success and 1 on failure
        int sendFile()
        {
            uint32_t bucket = 0;
            uint32_t framesPerBucket = 0;
            DataFrame data_frame;

            if(info.bandwidth)
            {
                bucket = 1000000 / BUCKETS_PER_SEC;    // 1000000µs per sec
                int bytesPerBucket = info.bandwidth / BUCKETS_PER_SEC;
                framesPerBucket = bytesPerBucket / MAX_DATA_FRAME_SIZE;

                if(!framesPerBucket) {
                    std::cerr << "xcc_protocol_handler.xcc::DefaultProtocolHandler::sendFile::Error::Bandwidth setting too low. (min: " << (int) MAX_DATA_FRAME_SIZE * BUCKETS_PER_SEC << ")" << std::endl;
                    return 1;
                }
            }

            FileInfo file_info;
            file_info.stdi = info.read_stdin;
            file_info.filename = info.filePath;
            file_io = new FileIO(file_info);

            if(file_io->ErrorState()) {
                std::cerr << "xcc_protocol_handler.xcc::DefaultProtocolHandler::sendFile::Error::Could not open input path." << std::endl;
                return 1;
            }

            // send filename
            // create data frame header to transfer filename
            // filename characterized by order_counter == 0 && data_size > 0 && mode binary
            std::string filename = file_io->GetFilename();
            data_frame.setFlag(FLAG_DATA_FRAME);
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setData(const_cast<char *>(filename.c_str()), filename.size());

            int ret_val = socketIO->SendDataFrame(data_frame);
            if(ret_val == -1)
            {
                std::cerr << "xcc_protocol_handler.xcc::DefaultProtocolHandler::sendFile::Error sending filename." << std::endl;
                return 1;
            }
            
            data_frame.reset();

            // start sending file data
            char inBuffer[MAX_DATA_BLOCK_SIZE] = { 0 };
            int bytes_read = 0;
            int flush_counter = 0;
            uint32_t frameBudget = framesPerBucket;
            uintmax_t progress = 0;
            auto start_time = std::chrono::high_resolution_clock::now();
            while(file_io->isGood())
            {
                // read data + prepapre data frame
                bytes_read = file_io->ReadBytes(inBuffer, DATA_BLOCK_SIZE);
                data_frame.setFlag(FLAG_DATA_FRAME);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setTransmissionID(info.TransmissionID);
                data_frame.setData(inBuffer, bytes_read);

                // send data frame
                ret_val = socketIO->SendDataFrame(data_frame);
                if(ret_val)
                {
                    std::cerr << "sendFile::Error sending file." << std::endl;
                    return 1;
                }
                data_frame.reset();

                // calculate/print progress
                progress += bytes_read;
                if(info.progress) {
                    std::cout << "\rProgress (Bytes): " << progress;
                    if(!(flush_counter % 20)) std::cout.flush();
                    flush_counter++;
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

            // send end-of-transmission frame
            data_frame.reset();
            data_frame.setTransmissionID(info.TransmissionID);
            data_frame.setFlag(FLAG_END_OF_TRANSMISSION);
            data_frame.setData(nullptr, 0);

            // send final EOT frame
            ret_val = socketIO->SendDataFrame(data_frame);
            if(ret_val)
            {
                std::cerr << "sendFile::Error closing file transfer." << std::endl;
                return 1;
            }

            if(info.stats || info.progress)  {
                if(info.progress) std::cout << "\n";
                std::cout << "Total bytes sent: " << progress << "\n";
            }

            return 0;
        }

        void ctrl_loop()
        {
            CTRL_FRAME srv_ctrl_frame;

            int err = 0;
            bool running = true;

            while(running)
            {
                switch (state)
                {
                    case STATE_GET_TYPE:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_GET_TYPE" << std::endl;
                        #endif
                    
                        dtype = info.dtype;
                        if(dtype == TYPE_NONE)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Could not set transfer mode." << std::endl;
                            state = STATE_STOP_CLIENT;
                        } else {
                            state = STATE_SEND_INIT_CTRL_FRAME;
                            socketIO->SetTransferMode(dtype);
                            socketIO->SetTransmissionID(info.TransmissionID);
                        }
                        break;
                    }

                    case STATE_SEND_INIT_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_SEND_INIT_CTRL_FRAME" << std::endl;
                        #endif

                        socketIO->SetTransmissionID(info.TransmissionID);
                        err = socketIO->SendCtrlFrameEncrypted();
                        if(err)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Could not send ctrl frame." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_RCV_SRV_CTRL_FRAME;
                        break;
                    }

                    case STATE_RCV_SRV_CTRL_FRAME:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_RCV_SRV_CTRL_FRAME" << std::endl;
                        #endif

                        err = eph::RcvServerCtrlFrame(clientSocket, srv_ctrl_frame);
                        if(err) {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Could not receive ctrl frame from server." << std::endl;
                            state = STATE_STOP_CLIENT;
                        } else
                            state = STATE_RCV_SRV_IV;
                        break;
                    }

                    case STATE_RCV_SRV_IV:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_RCV_SRV_IV" << std::endl;
                        #endif

                        // set IV on dec for server encryption
                        err = socketIO->SetIVFromSocket(CNL_RCV);
                        if(err) {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Could not receive IV from server." << std::endl;
                            state = STATE_STOP_CLIENT;
                        } else
                            state = STATE_SET_INITIAL_KEY;
                        break;
                    }

                    case STATE_SET_INITIAL_KEY:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_SET_INITIAL_KEY" << std::endl;
                        #endif

                        // set encryption keys
                        switch (info.pv)
                        {
                            case PV_X25519:
                                err = socketIO->PublicKeyExchange();
                                break;

                            case PV_PSK_X25519:
                                err = socketIO->EncReadKeyFromFile(info.keyFile);
                                err |= socketIO->DecReadKeyFromFile(info.keyFile);
                                err |= socketIO->PublicKeyExchangeAuthenticated();
                                break;
                            
                            default:
                                err = 1;
                                break;
                        }
  
                        if(err)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Error setting key." << std::endl;
                            state = STATE_STOP_CLIENT;
                        }
                        else
                            state = STATE_SEND_DATA;
                        break;
                    }

                    case STATE_SEND_DATA:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_SEND_DATA" << std::endl;
                        #endif

                        if(dtype == TYPE_BIN)
                        {
                            err = sendFile();
                        }
                        else if(dtype == TYPE_TXT)
                        {
                            err = sendMessage();
                        }

                        if(err)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::Send data returned an error." << std::endl;
                            state = STATE_STOP_CLIENT;
                            break;
                        }
                        state = STATE_RCV_FINAL_ACK;                        
                        break;
                    }

                    case STATE_RCV_FINAL_ACK:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_RCV_FINAL_ACK" << std::endl;
                        #endif

                        ACK_ERROR_CODE ackErr = socketIO->GetAckFromSocket();
                        if(ackErr)
                        {
                            error = 1;
                            std::cerr << "xcc_protocol_handler.hpp::DefaultProtocolHandler::ctrl_loop::ERROR::Final ack error." << std::endl;
                        }
                        state = STATE_STOP_CLIENT;
                    }

                    case STATE_STOP_CLIENT:
                    {
                        #ifdef DEBUG
                        std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::STATE::STATE_STOP_CLIENT" << std::endl;
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
        EncryptedProtocolHandler(TransferInfo ti) {

            #ifdef DEBUG
            std::cout << "xcc_protocol_handler.hpp::EncryptedProtocolHandler::Starting Encrypted Protocol Manager!" << std::endl;
            #endif

            info = ti;
            clientSocket = info.clientSocket;

            socketIO = new SocketIO_Manager(clientSocket, info.secVer, info.pv);
            DATA_BLOCK_SIZE = socketIO->GetDataBlockSize();
                
            state = STATE_GET_TYPE;
            ctrl_loop();
        }

        ~EncryptedProtocolHandler() {
            delete socketIO;
            if(file_io) delete file_io;
        }

        int getErrState() { return error; }
};


#endif
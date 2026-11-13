#ifndef SOCKETIO_HANDLER_HPP
#define SOCKETIO_HANDLER_HPP

#include <cryptopp/xed25519.h>

#include "xcc.hpp"
#include "crypto_handler.hpp"

enum CHANNEL_TYPE
{
    CNL_RCV,
    CNL_SND
};

struct CHANNEL_INFO
{
    byte TransmissionID = 0;
    uint32_t frame_order_nbr = 0;
    DATA_TYPE mode = TYPE_NONE;
    PROTOCOL_VERSION pv = PV_NONE;
    SECURITY_VERSION sv = SV_NONE;
};

void printError(std::string err_msg) {
    #ifdef SERVER
    *global_info.stderrStream << tool::current_time_string() << "::" << err_msg << std::endl;
    #endif

    #ifdef CLIENT
    std::cerr << err_msg << std::endl;
    #endif
}

class PublicKeyManager
{
    private:
        CryptoPP::x25519 keyx;
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::byte privateKey[CryptoPP::x25519::SECRET_KEYLENGTH] = { 0 };
        CryptoPP::byte publicKey[CryptoPP::x25519::PUBLIC_KEYLENGTH] = { 0 };
        CryptoPP::byte sharedKey[CryptoPP::x25519::SHARED_KEYLENGTH] = { 0 };

    public:
        PublicKeyManager()
        {
            keyx.GenerateKeyPair(rng, privateKey, publicKey);
        }

        ~PublicKeyManager()
        {
            memset(privateKey, 0x00, CryptoPP::x25519::SECRET_KEYLENGTH);
            memset(publicKey, 0x00, CryptoPP::x25519::PUBLIC_KEYLENGTH);
            memset(sharedKey, 0x00, CryptoPP::x25519::SHARED_KEYLENGTH);
        }

        int GetSharedKeyLength() { return CryptoPP::x25519::SHARED_KEYLENGTH; }

        int GetPublicKeyLength() { return CryptoPP::x25519::PUBLIC_KEYLENGTH; }

        CryptoPP::byte *GetPublicKey() { return publicKey; }

        CryptoPP::byte *GetSharedKey() { return sharedKey; }

        CryptoPP::byte *GenerateSharedKey(CryptoPP::byte *partnerPublicKey)
        {
            if(keyx.Agree(sharedKey, privateKey, partnerPublicKey))
                return sharedKey;
            else
                return nullptr;
        }
};

class SocketIO_Manager
{
    private:
        int error = 0;
        int ClientSocket = 0;
        int DATA_BLOCK_SIZE = 0;
        char ioBuffer[MAX_DATA_FRAME_SIZE];
        char plnBuffer[MAX_DATA_FRAME_SIZE + 1];
        PublicKeyManager pkm;
        CHANNEL_INFO rcv_chn_info;
        CHANNEL_INFO snd_chn_info;
        Decryption *dec = nullptr;
        Encryption *enc = nullptr;

        void init() {
            dec = new Decryption(rcv_chn_info.sv);
            enc = new Encryption(snd_chn_info.sv);
            int block_size_enc = enc->getDataBlockSize();
            int block_size_dec = dec->getDataBlockSize();
            if(block_size_dec == block_size_enc) DATA_BLOCK_SIZE = block_size_enc;
            else error = 1;
        }

        // return 0 on success, -1 on failure
        int SendDataBuffer(int sock, void* buffer, int length)
        {
            if(length > MAX_DATA_FRAME_SIZE)
            {
                std::string error_msg = "xcc_protocol_handler.hpp::sendDataBuffer::ERROR::max data frame size exceeded";
                printError(error_msg);
                return -1;
            }
            return sio::write_to_socket(sock, buffer, length);
        }

        int VerifyDataFrame(DATA_FRAME_HEADER &data_header) {

            if(data_header.transmission_id != rcv_chn_info.TransmissionID) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::VerifyDataFrame::Error::Transmission ID missmatch.";
                printError(error_msg);
                return 1;
            }

            // test for correct frame order
            if(data_header.order_nbr != rcv_chn_info.frame_order_nbr) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::VerifyDataFrame::Error::Frame out of order.";
                printError(error_msg);
                return 1;
            }

            // test if data length fits protocol expectation
            if(data_header.data_size > DATA_BLOCK_SIZE) {
                *global_info.stderrStream << tool::current_time_string() << "::socketIO_handler.hpp::SocketIO_Manager::VerifyDataFrame::Error::Data frame data size too large." << std::endl;
                return 1;
            }

            // test data integrity
            chksum_t ChkSum = tool::fletcher16(&plnBuffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
            if(ChkSum != data_header.chksum) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::VerifyDataFrame::Error::Checksum missmatch.";
                printError(error_msg);
                return 1;
            }

            return 0;
        }

        int SendLocalPublicKey()
        {
            return sio::write_to_socket(ClientSocket, pkm.GetPublicKey() , CryptoPP::x25519::PUBLIC_KEYLENGTH);
        }

        int SendLocalPublicKeyEncrypted()
        {
            DataFrame data_frame;
            CryptoPP::byte *pkey;

            pkey = pkm.GetPublicKey();

            #ifdef DEBUG
            std::cout << "socketIO_handler.hpp::SocketIO_Manager::SendLocalPublicKeyEncrypted::local/sent public key:\n" << tool::byteToHex(pkey, CryptoPP::x25519::SHARED_KEYLENGTH, 'l') << std::endl;
            #endif

            data_frame.setFlag(FLAG_KEY_DATA);
            data_frame.setTransmissionID(snd_chn_info.TransmissionID);
            data_frame.setData(pkey, CryptoPP::x25519::PUBLIC_KEYLENGTH);

            int ret_val = SendDataFrame(data_frame);

            return ret_val;
        }

        // return pointer to sharedKey or nullptr on failure
        CryptoPP::byte *GenerateSharedKey()
        {
            CryptoPP::byte ppkey[CryptoPP::x25519::PUBLIC_KEYLENGTH];

            int err = sio::read_from_socket(ClientSocket, ppkey, CryptoPP::x25519::PUBLIC_KEYLENGTH, MSG_WAITALL);
            if(!err)
                return pkm.GenerateSharedKey(ppkey);
            return nullptr;
        }

        // return pointer to sharedKey or nullptr on failure
        CryptoPP::byte *GenerateSharedKeyAuthenticated()
        {
            CryptoPP::byte *partner_key_pointer = reinterpret_cast<CryptoPP::byte *>(&plnBuffer[DATA_FRAME_HEADER_SIZE]);

            if(ReadDataFrame() == CryptoPP::x25519::PUBLIC_KEYLENGTH) {

                #ifdef DEBUG
                std::cout << "socketIO_handler.hpp::SocketIO_Manager::GenerateSharedKeyAuthenticated::received/remote public key:\n" << tool::byteToHex(partner_key_pointer, CryptoPP::x25519::SHARED_KEYLENGTH, 'l') << std::endl;
                #endif

                return pkm.GenerateSharedKey(partner_key_pointer);
            }

            return nullptr;
        }

        void SetSharedKey(CryptoPP::byte *sharedKey)
        {
            enc->setKey(sharedKey);
            dec->setKey(sharedKey);
        }

    public:
        SocketIO_Manager(int sock, SECURITY_VERSION sv, PROTOCOL_VERSION pv) {
            ClientSocket = sock;
            rcv_chn_info.pv = pv;
            rcv_chn_info.sv = sv;
            snd_chn_info.pv = pv;
            snd_chn_info.sv = sv;

            init();
        }

        ~SocketIO_Manager() {
            if(dec) delete dec;
            if(enc) delete enc;
            memset(plnBuffer, 0x00, MAX_DATA_FRAME_SIZE + 1 );
        }

        // bool isEncrypted() { return encrypted; }

        int GetError() { return error; }

        int GetDataBlockSize() { return DATA_BLOCK_SIZE; }

        char *GetPlnBuffer() { return plnBuffer; }

        void SetFrameOrder(int nbr) {
            snd_chn_info.frame_order_nbr = nbr;
            rcv_chn_info.frame_order_nbr = nbr;
        }

        int PublicKeyExchange()
        {
            CryptoPP::byte *sharedKey = nullptr;

            int err = SendLocalPublicKey();
            if(err)
            {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchange::Error::SendLocalPublicKey returned with error!";
                printError(error_msg);
                return 1;
            }

            sharedKey = GenerateSharedKey();
            if(!sharedKey)
            {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchange::Error::Generating the shared key failed!";
                printError(error_msg);
                return 1;
            }

            #ifdef DEBUG
            std::cout << "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchange::agreed shared key:\n" << tool::byteToHex(sharedKey, CryptoPP::x25519::SHARED_KEYLENGTH, 'l') << std::endl;
            #endif

            SetSharedKey(sharedKey);

            return 0;
        }

        int PublicKeyExchangeAuthenticated()
        {
            if(SendLocalPublicKeyEncrypted())
            {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchangeAuthenticated::Error::SendLocalPublicKeyEncrypted returned with error!";
                printError(error_msg);
                return 1;
            }

            CryptoPP::byte *sharedKey = GenerateSharedKeyAuthenticated();

            if(!sharedKey)
            {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchangeAuthenticated::Error::Generating the shared key failed!";
                printError(error_msg);
                return 1;
            }

            #ifdef DEBUG
            std::cout << "socketIO_handler.hpp::SocketIO_Manager::PublicKeyExchangeAuthenticated::agreed shared key:\n" << tool::byteToHex(sharedKey, CryptoPP::x25519::SHARED_KEYLENGTH, 'l') << std::endl;
            #endif

            SetSharedKey(sharedKey);

            SetFrameOrder(0);

            return 0;
        }

        int GetFrameOrderRcvChn() { return rcv_chn_info.frame_order_nbr; }

        int GetFrameOrderSndChn() { return snd_chn_info.frame_order_nbr; }

        // reads a data frame from socket into plnBuffer
        // returns amount of user data received on success (>0), return value does not include data_header size only the payload size
        // returns -1 on failure (return < 0)
        // returns EOT when received an EOT data frame (-2)
        // data in pln_buffer starts at [DATA_FRAME_HEADER_SIZE]
        int ReadDataFrame() {
            DATA_FRAME_HEADER data_header;

            // read encrypted data frame
            int err = sio::read_from_socket(ClientSocket, ioBuffer, MAX_DATA_FRAME_SIZE, MSG_WAITALL);
            if(err) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::ReadDataFrame::Error::Error reading frame from socket.";
                printError(error_msg);
                return -1;
            }

            // decrypt data from rcv_buffer to pln_buffer
            bool verified = dec->decrypt(ioBuffer, plnBuffer, MAX_DATA_FRAME_SIZE);
            if(!verified) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::ReadDataFrame::Error::Frame verification failed.";
                printError(error_msg);
                return -1;
            }

            // copy data_header from buffer
            memcpy(&data_header, plnBuffer, DATA_FRAME_HEADER_SIZE);

            int verify_err = VerifyDataFrame(data_header);
            if(verify_err) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::ReadDataFrame::Error::Frame header verification failed.";
                printError(error_msg);
                return -1;
            }
            
            rcv_chn_info.frame_order_nbr++;

            // close connection at 32bit rollover
            if(rcv_chn_info.frame_order_nbr == 0) {
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::ReadDataFrame::Warning::Maximum frame count reached for transmission.";
                printError(error_msg);
                return -1;
            }

            // test for EOT frame
            int return_value = data_header.data_size;
            if(data_header.data_size == 0) {
                if(data_header.flags & FLAG_END_OF_TRANSMISSION) return_value = EOT;
                else {
                    std::string error_msg = "::socketIO_handler.hpp::SocketIO_Manager::ReadDataFrame::Error::Empty (non-EOT) frame received.";
                    printError(error_msg);
                    return -1;
                }
            }

            return return_value;
        }

        // encrypts a data_frame if required and sends it
        // sets frame order number and transmission id
        // returns 0 on success, -1 on failure
        int SendDataFrame(DataFrame &df) {
            int send_err = 0;

            df.setOrder(snd_chn_info.frame_order_nbr);
            df.setTransmissionID(snd_chn_info.TransmissionID);

            // encrypt data and send
            int transmit_size = enc->encrypt(df.getTransmitBuffer(), ioBuffer, df.frameSize());
            send_err = SendDataBuffer(ClientSocket, ioBuffer, transmit_size);

            snd_chn_info.frame_order_nbr++;

            return send_err;
        }

        // generate ctrl_frame for encryption, appends iv to ctrl_frame
        int SendCtrlFrameEncrypted()
        {
            ControlFrame control_frame;
            int iv_size = enc->getIVSize();
            CryptoPP::byte *iv = enc->getIV();

            control_frame.setProtocolVer(snd_chn_info.pv);
            control_frame.setSecurityVer(snd_chn_info.sv);
            control_frame.setFlag(FLAG_NEW_TRANSMISSION | FLAG_ENCRYPTED);
            control_frame.setTransmissionID(snd_chn_info.TransmissionID);
            if(snd_chn_info.mode == TYPE_BIN) control_frame.setFlag(FLAG_BINARY_TRANSMISSION);

            char sendBuffer[CTRL_FRAME_SIZE + MAX_IV_SIZE];

            // ctrl_frame to send buffer
            memcpy(sendBuffer, control_frame.getCtrlFrame(), CTRL_FRAME_SIZE);
            // add iv to send buffer
            memcpy(&sendBuffer[CTRL_FRAME_SIZE], iv, iv_size);

            // send CTRL FRAME
            return sio::write_to_socket(ClientSocket, sendBuffer, CTRL_FRAME_SIZE + iv_size);
        }

        ACK_ERROR_CODE GetAckFromSocket()
        {
            ACK_FRAME ack;
            int ret_val = ReadDataFrame();
            if(ret_val != ACK_FRAME_SIZE)
            {
                std::string error_msg = "socketIO_handler.hpp::GetAckFromSocket::ERROR::Could not read ack from socket.";
                printError(error_msg);
                return ACK_GENERAL_ERR;
            }
            
            memcpy(&ack, &plnBuffer[DATA_FRAME_HEADER_SIZE], ACK_FRAME_SIZE);
            
            if(strcmp(ack.ack, "ACK"))
            {
                std::string error_msg = "socketIO_handler.hpp::GetAckFromSocket::ERROR::malformed ack";
                printError(error_msg);
                return ACK_GENERAL_ERR;
            }
            return ack.error;
        }

        int SendAck(ACK_ERROR_CODE err, byte TransmissionID)
        {
            ACK_FRAME ack;
            DataFrame data_frame;

            #ifdef DEBUG
            std::cout << "socketIO_handler.hpp::SendAck::TransmissionID: " << (int) TransmissionID << std::endl;
            #endif

            ack.error = err;

            data_frame.setFlag(FLAG_ACK_FRAME);
            data_frame.setTransmissionID(TransmissionID);
            data_frame.setOrder(snd_chn_info.frame_order_nbr);
            data_frame.setData(&ack, ACK_FRAME_SIZE);

            return SendDataFrame(data_frame);
        }

        void SetTransferMode(DATA_TYPE mode) { 
            snd_chn_info.mode = mode;
            rcv_chn_info.mode = mode;
        }

        void SetTransmissionID(byte tid) {
            snd_chn_info.TransmissionID = tid;
            rcv_chn_info.TransmissionID = tid;
        }

        // read iv from socket and sets it on selected module
        // return 0 on success, -1 on failure
        int SetIVFromSocket(CHANNEL_TYPE ct)
        {
            int err = sio::read_from_socket(ClientSocket, ioBuffer, dec->getIVSize(), MSG_WAITALL);
            if(err)
            {
                std::string error_msg = "::socketIO_handler.hpp::SocketIO_Manager::SetIVFromSocket::Error::Could not read iv from socket.";
                printError(error_msg);
                return err;
            }

            switch (ct)
            {
            case CNL_RCV:
                dec->setIV(ioBuffer);
                break;
            
            case CNL_SND:
                enc->setIV(ioBuffer);
                break;
            
            default:
                std::string error_msg = "socketIO_handler.hpp::SocketIO_Manager::SetIVFromSocket::Error::Channel type unknown.";
                printError(error_msg);
                return -1;
                break;
            }

            return 0;
        }

        int DecReadKeyFromFile(std::string filename) { return dec->readKey(filename); }

        int EncReadKeyFromFile(std::string filename) { return enc->readKey(filename); }

        Encryption *getEncryptionModule() { return enc; }

        Decryption *getDecryptionModule() { return dec; }
};

#endif

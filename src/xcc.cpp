#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include "xchange.hpp"

enum TransferMode
{
    MODE_TEXT,
    MODE_FILE,
    MODE_NONE
};

struct CliArgs
{
    std::string serverIP = "";
    std::string port = std::to_string(DEFAULT_PORT);
    std::string msg = "";
    std::string outfile = "";
    bool stats = false;
    bool help = false;
    bool version = false;
};

class ControlFrame;
class DataFrame;
struct TransferInfo
{
    int clientSocket = 0;
    const char *msg = nullptr;
    const char *filePath = nullptr;
    TransferMode mode = MODE_NONE;
    ControlFrame *ctrlFrame = nullptr;
    DataFrame *dataFrame = nullptr;
    bool stats = false;
};

class ControlFrame
{
    private:
        CTRL_FRAME frame_intern, frame_extern;

        void resetCtrlFrame() { frame_intern = { .flags = 0x00, .transmission_id = 0x00 }; }

    public:
        void setFlag(byte flag) { frame_intern.flags |= flag; }

        void setTransmissionID(byte id) { frame_intern.transmission_id = id; }

        CTRL_FRAME *getCtrlFrame()
        {
            memcpy(&frame_extern, &frame_intern, CTRL_FRAME_SIZE);
            resetCtrlFrame();
            return &frame_extern;
        }
};

class DataFrame
{
    private:
        DATA_TYPE type = TYPE_NONE;
        const char *dataPointer = nullptr;
        char transmitBuffer[DATA_FRAME_HEADER_SIZE + MAX_DATA_BLOCK_SIZE] = { 0 };
        DATA_FRAME_HEADER header;

        void setChkSum()
        {
            char *bufferPointer = const_cast<char *>(dataPointer);
            header.chksum = tool::bufferChkSum(bufferPointer, header.data_size);
        }

        void constructDataFrame()
        {
            // add chksum to header
            setChkSum();

            // write header to transmit buffer
            memcpy(&transmitBuffer, &header, DATA_FRAME_HEADER_SIZE);

            // write data to transmit buffer
            memcpy(&transmitBuffer[DATA_FRAME_HEADER_SIZE], dataPointer, header.data_size);
        }

        void resetHeader()
        {
            header.chksum = 0x00;
            header.data_size = 0x0000;
            header.flags = 0x00;
            header.order_nbr = 0x00000000;
            header.transmission_id = 0x00;
        }

    public:
        void setFlag(byte flag) { header.flags |= flag; }
        
        void setTransmissionID(byte id) { header.transmission_id = id; }

        void setOrder(uint32_t nbr) { header.order_nbr = nbr; }

        void setData(void *data, uint16_t size)
        {
            dataPointer = reinterpret_cast<const char *>(data);
            header.data_size = size;
        }

        size_t frameSize() { return DATA_FRAME_HEADER_SIZE + header.data_size; }

        char *getTransmitBuffer()
        {
            constructDataFrame();
            return transmitBuffer;
        }

        void reset() { resetHeader(); }
};

void printHelp()
{
    const char *help_text = "xchange client help:\n \
    \nclient [Options] [Data:text|file]\n\n \
    -s <ip> Server IP (IPv4 address, no DNS resolve in this version)\n \
    -p <server tcp port> (defaults to 9009 if omitted)\n \
    -m 'message string' Send a message.\n \
    -f <file_path>  Path of file to send.\n \
    -S Print transfer statistics.\n \
    -h Print this help.\n \
    The program takes either a message (-m) or a file (-f).\n\n \
    Examples:\n\n \
    client -s 192.168.100.200 -m 'do not forget this message'\n \
    client -s 192.168.100.200 -p 10000 -f /path/to/my/file";

    std::cout << help_text << std::endl;
}

int parseArgs(int argc, char* argv[], CliArgs &args)
{
    std::string tmp_str = "";
    for(int i = 1; i < argc; i++)
    {
        tmp_str = argv[i];

        if( tmp_str == "-s" )
        {
            i++;
            args.serverIP = argv[i];
            continue;
        }

        if( tmp_str == "-p" )
        {
            i++;
            args.port = argv[i];
            continue;
        }

        if( tmp_str == "-m" )
        {
            i++;
            args.msg = argv[i];
            continue;
        }

        if( tmp_str == "-f" )
        {
            i++;
            args.outfile = argv[i];
            continue;
        }

        if( tmp_str == "-S" )
        {
            args.stats = true;
            continue;
        }

        if( tmp_str == "-h" )
        {
            i++;
            args.help = true;
            break;
        }

        if( tmp_str == "-v" )
        {
            i++;
            args.version = true;
            break;
        }
    }

    if(args.help)
    {
        printHelp();
        return 0;
    }

    if(args.version)
    {
        std::cout << "exchange client version: " << program_version_str << std::endl;
        return 0;
    }

    if(args.outfile.size() > 0)
    {
        if(tool::filename_from_path(args.outfile.c_str()).size() > MAX_FILENAME_LENGTH)
        {
            std::cerr << "Filename exceeds MAX_FILENAME_LENGTH: " << MAX_FILENAME_LENGTH << std::endl;
            return 1;
        }
    }

    if((args.msg.size() > 0) && (args.outfile.size() > 0))
    {
        std::cerr << "Argument Error! Only -f <outfile> or -m <message> is allowed. Not both options at once." << std::endl;
        return 1;
    }

    if(!(args.serverIP.size() > 0))
    {
        std::cerr << "Missing Server IP." << std::endl;
        return 1;
    }

    return 0;
}

int getSocketQueueSize(int sock)
{
    int total_queue_size = 0;

    socklen_t optlen = sizeof(total_queue_size);

    if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &total_queue_size, &optlen) < 0) {
        perror("getsockopt SO_SNDBUF failed");
        return -1;
    }

    int usable_buffer_size = total_queue_size / 2;

    //return total_queue_size;
    return usable_buffer_size;
}

// returns 0 on success and -1 on failure
int write_to_socket(int sock, void *buff, size_t bufferSize)
{
    // cast buffer into write accepted format
    const char *buffer = const_cast<const char *>(static_cast<char *>(buff));

    // determine the socket queue length
    size_t socket_queue_length = getSocketQueueSize(sock);
    if(socket_queue_length < 0)
    {
        int err = errno;
        const char *errName = strerrorname_np(err);
        const char *errDesc = strerrordesc_np(err);
        std::cerr << "\nwrite_to_socket::ERROR::Error at getting queue length (" << errName << ")\n";
        std::cerr << "write_to_socket::ERROR::" << errDesc << std::endl;
        return -1;
    }

    // max count of bytes to send at once
    int write_at_once = 0;
    if(bufferSize > socket_queue_length)
        write_at_once = socket_queue_length;
    else
        write_at_once = bufferSize;

    bool active = true;
    int retry_count_err = 0;
    int resend_count = 0;
    int ret_val = 0;
    int bytes_sent = 0;
    int bytes_to_send = 0;
    int bytes_remaining = bufferSize;
    while(active)
    {
        if(retry_count_err > MAX_SEND_RETRY_ON_ERR)
        {
            std::cerr << "write_to_socket::ERROR::maximum retry_on_err count exceeded" << std::endl;
            return -1;
        }

        if(resend_count > MAX_RESEND)
        {
            std::cerr << "write_to_socket::ERROR::maximum resend attempts exceeded" << std::endl;
            return -1;
        }

        if(bytes_remaining >= write_at_once)
            bytes_to_send = write_at_once;
        else
            bytes_to_send = bytes_remaining;
        
        ret_val = write(sock, &buffer[bytes_sent], bytes_to_send);
        if(ret_val < 0)
        {
            int err = errno;
            const char *errName = strerrorname_np(err);
            const char *errDesc = strerrordesc_np(err);
            std::cerr << "\nwrite_to_socket::ERROR::write returned with error: " << errName << "\n";
            std::cerr << "write_to_socket::ERROR::" << errDesc << std::endl;
            if(err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
            {
                tool::pauseThread();
                retry_count_err++;
                std::cerr << "write_to_socket::WARNING::retry_on_err count: " << retry_count_err << std::endl;
                continue;
            }
            return -1;
        }
        else if(ret_val > 0)
        {
            bytes_sent += ret_val;
            bytes_remaining -= ret_val;
            if(ret_val < bytes_to_send) tool::pauseThread();
        }

        resend_count++;
        
        if(bytes_remaining == 0) active = false;
    }
    return 0;
}

// returns 0 on success and 1 on failure
int sendText(int sock, const char *data, ControlFrame *control_frame, DataFrame *data_frame)
{
    // sending data
    int data_size = strlen(data);
    byte TransmissionID = 0x01;

    // create initial CTRL_FRAME
    control_frame->setFlag(FLAG_NEW_TRANSMISSION);
    control_frame->setTransmissionID(TransmissionID);

    // send CTRL FRAME
    CTRL_FRAME *ctrl_frame = control_frame->getCtrlFrame();
    //send(sock, ctrl_frame, CTRL_FRAME_SIZE, 0);
    // send_all_nonblocking(sock, ctrl_frame, CTRL_FRAME_SIZE);
    write_to_socket(sock, ctrl_frame, CTRL_FRAME_SIZE);

    // create data frame header
    data_frame->setFlag(FLAG_DATA_FRAME);
    data_frame->setTransmissionID(TransmissionID);
    data_frame->setOrder(0x00000001);
    char *data_buffer = const_cast<char *>(data);
    data_frame->setData(data_buffer, data_size);

    // send text message
    char *sendBuffer = const_cast<char *>(data_frame->getTransmitBuffer());
    // int send_err = write_to_socket(sock, data_frame->getTransmitBuffer(), data_frame->frameSize());
    int send_err = write_to_socket(sock, sendBuffer, data_frame->frameSize());
    if(send_err)
    {
        std::cerr << "Error sending message" << std::endl;
        return 1;
    }

    // closing the transmission
    data_frame->setData(nullptr, 0);
    data_frame->setFlag(FLAG_END_OF_TRANSMISSION);

    // send closing data frame
    send_err = write_to_socket(sock, sendBuffer, data_frame->frameSize());
    if(send_err)
    {
        std::cerr << "Error sending message" << std::endl;
        return 1;
    }

    return 0;
}

// returns 0 on success and 1 on failure
int sendFile(TransferInfo info)
{
    std::string filename = "";
    uintmax_t fileSize = 0;
    uint32_t order_counter = 0x00000000;
    byte TransmissionID = 0x01;

    int sock = info.clientSocket;
    const char *path = info.filePath;
    ControlFrame *control_frame = info.ctrlFrame;
    DataFrame *data_frame = info.dataFrame;

    filename = tool::filename_from_path(path);
    std::filesystem::path filePath = path;
    fileSize = std::filesystem::file_size(filePath);

    // create CTRL Frame
    control_frame->setFlag(FLAG_NEW_TRANSMISSION);
    control_frame->setFlag(FLAG_BINARY_TRANSMISSION);
    control_frame->setTransmissionID(TransmissionID);

    // send CTRL FRAME
    CTRL_FRAME *ctrl_frame = control_frame->getCtrlFrame();
    int bytes_sent = write_to_socket(sock, ctrl_frame, CTRL_FRAME_SIZE);

    // create data frame header to transfer filename
    // filename characterized by order_counter == 0 && data_size > 0 && mode binary
    const char *filenamePointer = filename.c_str();
    data_frame->setFlag(FLAG_DATA_FRAME);
    data_frame->setTransmissionID(TransmissionID);
    data_frame->setOrder(order_counter);
    data_frame->setData(const_cast<char *>(filenamePointer), filename.size());

    // send filename in data frame 0
    bytes_sent = write_to_socket(sock, data_frame->getTransmitBuffer(), data_frame->frameSize());
    if(bytes_sent == -1)
    {
        std::cerr << "sendFile::Error sending Filename." << std::endl;
        return 1;
    }

    // start sending file data
    char inBuffer[MAX_DATA_BLOCK_SIZE] = { 0 };
    int bytes_read = 0;
    int send_bytes = 0;
    std::ifstream is(path, std::ifstream::binary);

    int percent = 0;
    int percent_last = 0;
    uintmax_t progress = 0;
    while(is.good())
    {
        is.read(inBuffer, MAX_DATA_BLOCK_SIZE); 
        bytes_read = is.gcount();
        data_frame->setOrder(++order_counter);
        data_frame->setTransmissionID(TransmissionID);
        data_frame->setData(inBuffer, bytes_read);
        send_bytes = write_to_socket(sock, data_frame->getTransmitBuffer(), data_frame->frameSize());
        if(send_bytes == -1)
        {
            std::cerr << "sendFile::Error sending file." << std::endl;
            is.close();
            return 1;
        }

        // print progress
        if(info.stats)
        {
            progress += bytes_read;
            percent = (((float) progress / (float) fileSize) * 100.0);
            if(percent > percent_last)
            {
                std::cout << "\rProgress: " << percent << "%";
                std::cout.flush();
            }
            percent_last = percent;
        }
    }
    if(info.stats)
        std::cout << "\nTransfered Bytes: " << progress << "\n";

    is.close();

    // send end-of-transmission frame
    data_frame->setOrder(++order_counter);
    data_frame->setTransmissionID(TransmissionID);
    data_frame->setFlag(FLAG_END_OF_TRANSMISSION);
    data_frame->setData(nullptr, 0);

    send_bytes = write_to_socket(sock, data_frame->getTransmitBuffer(), data_frame->frameSize());
    if(send_bytes == -1)
    {
        std::cerr << "sendFile::Error closing file transfer." << std::endl;
        return 1;
    }

    return 0;
}

uint16_t getPort(CliArgs &params)
{
    uint16_t port = 0;

    try
    {
        port = std::stoul(params.port);
    }
    catch(const std::invalid_argument &e)
    {
        std::cerr << "std::invalid_argument::" << e.what() << std::endl;
        std::cerr << "Port -p must be a number." << std::endl;
        exit(1);
    }
    catch(const std::out_of_range &e)
    {
        std::cerr << "std::out_of_range::" << e.what() << std::endl;
        exit(1);
    }
    if(port > 65535)
    {
        std::cerr << "Port can not be greater than 65535." << std::endl;
        exit(1);
    }

    return port;
}

int transferData(TransferInfo &transfer_info)
{
    int ret_val = 0;

    switch (transfer_info.mode)
    {
        case MODE_TEXT:
        {
            ret_val = sendText(transfer_info.clientSocket, transfer_info.msg, transfer_info.ctrlFrame, transfer_info.dataFrame);
            break;
        }
        case MODE_FILE:
        {
            // const char *filePath = transfer_info.filePath;
            //sendFile(transfer_info.clientSocket, filePath, transfer_info.ctrlFrame, transfer_info.dataFrame);
            ret_val = sendFile(transfer_info);
            break;        
        }
        case MODE_NONE:
        {
            std::cerr << "No transfer mode selected!" << std::endl;
            ret_val = 1;
        }
    }

    return ret_val;
}

int main(int argc, char* argv[])
{
    CliArgs params;
    uint16_t port = 0x0000;
    uint32_t serverIP = 0x00000000;
    DataFrame data_frame;
    ControlFrame control_frame;

    // parse command line arguments
    int parseErr = parseArgs(argc, argv, params);
    if(parseErr)
    {
        std::cerr << "Closing application due to argument error!" << std::endl;
        return 1;
    }

    // exit on help or version
    if(params.help | params.version) return 0;

    port = getPort(params);

    TransferInfo transfer_info;
    transfer_info.stats = params.stats;
    transfer_info.dataFrame = &data_frame;
    transfer_info.ctrlFrame = &control_frame;
    if(params.msg.size() > 0) transfer_info.msg = params.msg.c_str();
    if(params.outfile.size() > 0) transfer_info.filePath = params.outfile.c_str();

    // set operational mode
    if(params.msg.size() > 0) transfer_info.mode = MODE_TEXT;
    if(params.outfile.size() > 0) transfer_info.mode = MODE_FILE;

    // specifying server address
    serverIP = tool::ip_from_str(params.serverIP);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(serverIP);

    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    //int clientSocket = socket(AF_INET, SOCK_STREAM, 6);
    transfer_info.clientSocket = clientSocket;

    // sending connection request
    int connErr = connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress));
    if(connErr)
    {
        std::cerr << "main::Connection to server failed." << std::endl;
        close(clientSocket);
        return 1;
    }

    // sending data
    int transfer_error = transferData(transfer_info);
    if(transfer_error)
    {
        std::cerr << "main::TransferData returned an Error.\n";
        std::cerr << "Data may not have been transferred correctly!" << std::endl;
        close(clientSocket);
        return 1;
    }

    // close and test if socket transmitted all data without further errors
    int close_error = close(clientSocket);
    if(close_error)
    {
        int err = errno;
        const char *errName = strerrorname_np(err);
        const char *errDesc = strerrordesc_np(err);
        std::cerr << "main::ERROR::Error on closing the socket (" << errName << ") : " << errDesc << "\n";
        std::cerr << "Data may not have been transferred correctly!" << std::endl;
        return 1;
    }

    return 0;
}
// TODO:
// - by default at success print how many byte got successfully transfered
// - errors are alread included
// - implement a quiet option to silence success output (xxx bytes sent succesfully)
//   * maybe quiet has stages to also supress errors

#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>

#include "xcc_protocol_handler.hpp"

struct CliArgs
{
    std::string serverIP = "";
    std::string port = std::to_string(DEFAULT_PORT);
    std::string msg = "";
    std::string outfile = "";
    std::string bandwidth = "";
    std::string encryptionMode = "";
    std::string keyFile = "";
    bool stats = false;
    bool help = false;
    bool version = false;
};

const char *help_text =
"xchange client help:\n\n \
Usage:\n \
client [Options] [Data:text|file]\n\n \
-s <ip> Server IP (IPv4 address, no DNS resolve in this version)\n \
-p <server tcp port> (defaults to 9009 if omitted)\n \
-m 'message string' Send a message.\n \
-f <file_path>  Path of file to send.\n \
-e <encryption mode>    If ommitted datas transfered as plain text/unencrypted. Available encryption modes: cha (ChaCha20)\n \
-k <key file>   Key file used for selected encryption mode.\n \
-S Print transfer statistics.\n \
-b <bandwidth in byte>  Bytes sent per second. By default the client tries to write to the socket as fast as possible. Only applied when sending a file.\n \
-h Print this help.\n \
The program takes either a message (-m) or a file (-f).\n\n \
Examples:\n\n \
client -s 192.168.100.200 -m 'do not forget this message'\n \
client -s 192.168.100.200 -p 10000 -f /path/to/my/file";

void printHelp()
{
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

        if( tmp_str == "-e" )
        {
            i++;
            args.encryptionMode = argv[i];
            continue;
        }

        if( tmp_str == "-k" )
        {
            i++;
            args.keyFile = argv[i];
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

        if( tmp_str == "-b" )
        {
            i++;
            args.bandwidth = argv[i];
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

    if(args.encryptionMode.size() > 0 && args.keyFile.size() == 0)
    {
        std::cerr << "Missing encryption key." << std::endl;
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

// returns 0 if supported sec version was found, 1 if sec version could not be determind
int setSecurityVersion(CliArgs args, TransferInfo &transfer_info)
{
    if(!args.encryptionMode.size())
    {
        return 0;
    }
    else if (args.encryptionMode == "cha")
    {
        transfer_info.secVer = SV_CHACHA20;
        return 0;
    }
    return 1;
}


// returns 0 on success, 1 on failure
int selectProtocolHandler(TransferInfo transfer_info)
{
    int error = 0;

    switch (transfer_info.secVer)
    {
    case SV_CHACHA20:
    {
        ProtocolHandler_ChaCha20 ph_chacha20(transfer_info);
        error = ph_chacha20.getErrState();
        break;
    }
    
    default:
        ProtocolHandler_0001 ph(transfer_info);
        error = ph.getErrState();
        break;
    }

    return error;
}

int main(int argc, char* argv[])
{
    CliArgs params;
    uint16_t port = 0x0000;
    uint32_t serverIP = 0x00000000;
    ControlFrame control_frame;

    // ignore SIGPIPE in case writing to broken socket
    signal(SIGPIPE, SIG_IGN);

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
    if(params.keyFile.size()) transfer_info.keyFile = params.keyFile;
    if(params.msg.size() > 0) transfer_info.msg = params.msg.c_str();
    if(params.outfile.size() > 0) transfer_info.filePath = params.outfile.c_str();
    if(params.bandwidth.size() > 0)
    {
        try
        {
            transfer_info.bandwidth = std::stoll(params.bandwidth);
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            return 1;
        }
        if(transfer_info.bandwidth < MAX_DATA_FRAME_SIZE)
        {
            std::cerr << "Bandwidth in byte can not be smaller than the maximum frame size (" << MAX_DATA_FRAME_SIZE << " byte)" << std::endl;
            return 1;
        }
    }

    int err = setSecurityVersion(params, transfer_info);
    if(err)
    {
        std::cerr << "main::ERROR::Security Mode could not be identified." << std::endl;
        return 1;
    }

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
    transfer_info.clientSocket = clientSocket;

    // sending connection request
    int connErr = connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress));
    if(connErr)
    {
        std::cerr << "main::Connection to server failed." << std::endl;
        close(clientSocket);
        return 1;
    }

    //set socket timeout
    struct timeval timeout;
    timeout.tv_sec = SOCKET_RCVTIMEO_SEC;
    timeout.tv_usec = 0;
    int sock_opt_err = setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if(sock_opt_err)
    {
        std::cerr << "main::ERROR::Could not set socket timeout.\n"<< std::endl;
        // close(clientSocket);
        // return 1;
    }

    // select and start ProtocolHandler
    selectProtocolHandler(transfer_info);

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
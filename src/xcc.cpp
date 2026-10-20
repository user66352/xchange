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

#include <netinet/in.h>
#include <sys/socket.h>

#include "help.hpp"
#include "xcc_protocol_handler.hpp"

struct CliArgs
{
    std::string serverIP = "";
    std::string port = std::to_string(DEFAULT_PORT);
    std::string msg = "";
    std::string name = "";
    std::string mode = "";      // [message|file]
    std::string outfile = "";
    std::string bandwidth = "";
    std::string encryptionMode = "";
    std::string keyFile = "";
    bool progress = false;
    bool stats = false;
    bool help = false;
    bool version = false;
    bool readStdin = false;
};

void printHelp()
{
    std::cout << xcc_help_text << std::endl;
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

        // target port
        if( tmp_str == "-p" || tmp_str == "--port" )
        {
            i++;
            args.port = argv[i];
            continue;
        }

        // message, triggers message mode
        if( tmp_str == "-m" || tmp_str == "--message")
        {
            i++;
            args.msg = argv[i];
            continue;
        }

        // encryption method
        if( tmp_str == "-e" || tmp_str == "--encryption")
        {
            i++;
            args.encryptionMode = argv[i];
            continue;
        }

        // keyfile
        if( tmp_str == "-k" || tmp_str == "--key")
        {
            i++;
            args.keyFile = argv[i];
            continue;
        }

        // file name/path, triggers file mode
        if( tmp_str == "-f" || tmp_str == "--file")
        {
            i++;
            args.outfile = argv[i];
            continue;
        }

        // enable stats
        if( tmp_str == "-S" || tmp_str == "--stats")
        {
            args.stats = true;
            continue;
        }

        // enable progress
        if( tmp_str == "-P" || tmp_str == "--progress" )
        {
            args.progress = true;
            continue;
        }

        // set bandwidth
        if( tmp_str == "-b" || tmp_str == "--bandwidth")
        {
            i++;
            args.bandwidth = argv[i];
            continue;
        }

        // name to be used for file read from stdin
        if( tmp_str == "-n" || tmp_str == "--name" )
        {
            i++;
            args.name = argv[i];
            continue;
        }

        // read from stdin instead of file, triggers data being send in file mode
        if ( tmp_str == "--stdin" )
        {
            i++;
            args.readStdin = true;
            args.mode = argv[i];
            continue;
        }

        // print help
        if( tmp_str == "-h" || tmp_str == "--help")
        {
            i++;
            args.help = true;
            break;
        }

        // print version
        if( tmp_str == "-v" || tmp_str == "--version")
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
        std::cout << "xchange client\n";
        std::cout << "version: " << program_version_str << std::endl;
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

    if(args.name.size() & args.outfile.size())
    {
        std::cerr << "Filename and name can not be set at the same time." << std::endl;
        return 1;
    }

    if(args.readStdin)
    {
        if(args.outfile.size()) {
            std::cerr << "Reading a file incompatible to read from stdin." << std::endl;
            return 1;
        }

        if(args.mode == "file" && args.name.empty()) {
            std::cerr << "When selecting stdin as input for file transfere a file name must be provided (--name)." << std::endl;
            return 1;
        }

        if(args.mode == "message" && args.name.size() > 0) {
            std::cerr << "Stdin message transfere incompatible to option --name." << std::endl;
            return 1;
        }
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
    if (args.encryptionMode.empty())
    {
        transfer_info.secVer = SV_DEFAULT;
        transfer_info.pv = PV_DEFAULT;
    } else {
        transfer_info.secVer = selectionToSecVersionMap[args.encryptionMode];
        transfer_info.pv = proVersionLookupMap[transfer_info.secVer];
    }

    if(transfer_info.pv == PV_NONE || transfer_info.secVer == SV_NONE)
        return 1;

    return 0;
}

// TODO: needs to select a transmission id that is not used yet in use by any other ongoing connection
// returns 0 on success, 1 on failure
int selectProtocolHandler(TransferInfo transfer_info)
{

    #ifdef DEBUG
    std::cout << "xcc.cpp::selectProtocolHandler::enter selectProtocolHandler" << std::endl;
    #endif

    DefaultProtocolHandler ph_default(transfer_info);
    return ph_default.getErrState();
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
    transfer_info.progress = params.progress;
    transfer_info.read_stdin = params.readStdin;
    if(params.keyFile.size()) transfer_info.keyFile = params.keyFile;
    if(params.msg.size() > 0) transfer_info.msg = params.msg.c_str();
    if(params.outfile.size() > 0) transfer_info.filePath = params.outfile.c_str();
    if(params.name.size() > 0 && params.readStdin) transfer_info.filePath = params.name.c_str();
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
    if(params.readStdin) {
        if(params.mode == "message") transfer_info.mode = MODE_TEXT;
        if(params.mode == "file") transfer_info.mode = MODE_FILE;
    } else {
        if(params.msg.size() > 0) transfer_info.mode = MODE_TEXT;
        if(params.outfile.size() > 0) transfer_info.mode = MODE_FILE;
    }

    // specifying server address
    serverIP = tool::ip_from_str(params.serverIP);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(serverIP);

    // creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    transfer_info.clientSocket = clientSocket;

    // sending connection request
    int connErr = connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress));
    if(connErr)
    {
        std::cerr << "main::ERROR::Connection to server failed." << std::endl;
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
        std::cerr << "main::WARNING::Could not set socket timeout.\n"<< std::endl;
    }

    // select and start ProtocolHandler
    connErr = selectProtocolHandler(transfer_info);
    if(connErr) {
        std::cerr << "An error occurred during transfer!" << std::endl;
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
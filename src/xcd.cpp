// implementation of xchange daemon (xcd)

#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "xchange.hpp"

enum ProgramState
{
    STATE_WAIT_FOR_CONNECTION,
    STATE_START_CONN_MANAGER,
    STATE_RCV_CTRL_FRAME,
    STATE_RCV_DATA,
    STATE_RCV_DATA_FRAME,
    STATE_RCV_FILENAME,
    STATE_RCV_FILE_DATA,
    STATE_CM_CLOSE_CONN,
    STATE_EOT,
    STATE_STOP_SERVER
};

struct GlobalInfo
{
    std::ostream *stdoutStream = &std::cout;
    std::ostream *stderrStream = &std::cerr;
    std::string outDir = "";
    uint64_t maxFileLength = 0;
    uint64_t downloadFolderQuota = 0;
    int serverSocket = 0;
    bool filesToStdout = false;
} global_info;

struct Parameter
{
    std::string outDir = "";
    std::string msgOutFile = "";
    std::string logFile = "";
    uint32_t ip = INADDR_ANY;
    uint16_t port = DEFAULT_PORT;
    bool help = false;
    bool version = false;
};

void cleanUp();

void sigint_handler(int s)
{
    *global_info.stderrStream << "\r" << tool::current_time_string() << "::Received SIGINT, xcd terminated." << std::endl;
    cleanUp();
    exit(1);
}

class ConnectionManager
{
    private:
        GlobalInfo info;
        Parameter params;
        ProgramState state;
        CTRL_FRAME ctrl_frame;
        DATA_TYPE type = TYPE_NONE;
        char rcvBuffer[MAX_DATA_FRAME_SIZE + 1];    // +1 room for zero-termination a message
        int clientSocket = 0;
        int err_state = 0;
        uint32_t frame_order_nbr = 0;

        int rcv_ctrl_frame()
        {
            int recv_err = recv(clientSocket, &ctrl_frame, CTRL_FRAME_SIZE, MSG_WAITALL);
            if(recv_err == CTRL_FRAME_SIZE)
            {
                if(ctrl_frame.flags & FLAG_BINARY_TRANSMISSION)
                    type = TYPE_BIN;
                else
                    type = TYPE_TXT;

                return 0;
            }
            else
                return 1;
        }

        // return codes:
        // >0: amount of user data put into buffer, starting at data_buffer[DATA_FRAME_HEADER_SIZE]
        // -1: general recv error
        // -2: End-Of-Transmission, no data written to buffer (EOT)
        int rcv_data_frame(int sock, char *data_buffer)
        {
            DATA_FRAME_HEADER data_header;

            // read data_header from socket queue
            int recv_value = recv(sock, data_buffer, DATA_FRAME_HEADER_SIZE, MSG_WAITALL | MSG_PEEK);

            if(recv_value == DATA_FRAME_HEADER_SIZE)
            {
                // copy frame header to data_header struct
                memcpy(&data_header, data_buffer, DATA_FRAME_HEADER_SIZE);

                // test for correct frame order
                if(data_header.order_nbr != frame_order_nbr)
                {
                    *global_info.stderrStream << "\n" << tool::current_time_string() << "::ConnectionManager::rcv_data_frame::ERROR::Out-Of-Order frame received." << std::endl;
                    *global_info.stderrStream << "frame_order_nbr: " << frame_order_nbr << std::endl;
                    *global_info.stderrStream << "data_header.order_nbr: " << data_header.order_nbr << std::endl;
                    return -1;
                }

                // test if data_frame is valid and contains data
                if((data_header.transmission_id == ctrl_frame.transmission_id) && (data_header.data_size > 0))
                {
                    // read the entire data frame into buffer, removing it from the queue
                    int frame_size = DATA_FRAME_HEADER_SIZE + data_header.data_size;
                    recv_value = recv(sock, data_buffer, frame_size, MSG_WAITALL);
                    if((recv_value > MAX_DATA_FRAME_SIZE) || (recv_value != (DATA_FRAME_HEADER_SIZE + data_header.data_size)))
                    {
                        *global_info.stderrStream << "\n" << tool::current_time_string() << ":" << std::endl;
                        *global_info.stderrStream << "rcv_data_frame::Received an unexpected amount of data." << std::endl;
                        return -1;
                    }
                    
                    // test for data errors/corruption
                    uint8_t chk_sum = tool::bufferChkSum(&data_buffer[DATA_FRAME_HEADER_SIZE], data_header.data_size);
                    if(chk_sum != data_header.chksum)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::rcv_data_frame::ERROR::Checksum missmatch." << std::endl;
                        return -1;
                    }

                    // increase frame count at normal exit
                    frame_order_nbr++;

                    // recv_value >= 0 on success; data starts at data_buffer[DATA_FRAME_HEADER_SIZE]
                    return recv_value - DATA_FRAME_HEADER_SIZE;
                }
                //test end-of-transmission
                else if (recv_value == DATA_FRAME_HEADER_SIZE && data_header.flags & FLAG_END_OF_TRANSMISSION)
                {
                    recv_value = EOT;
                }
                else
                    recv_value = -1;
            }
            // returns here in case of EOT or a general error condition
            return recv_value;
        }

        void recv_message()
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
                        frame_order_nbr = 1;    // only 1 frame will be received per message
                        int ret_val = rcv_data_frame(clientSocket, rcvBuffer);
                        if(ret_val > 0)
                        {
                            // print message to stdout target
                            rcvBuffer[DATA_FRAME_HEADER_SIZE + ret_val] = 0;
                            const char *msg = &(rcvBuffer[DATA_FRAME_HEADER_SIZE]);
                            *global_info.stdoutStream << tool::current_time_string() << "::Message:\n";
                            *global_info.stdoutStream << msg << "\n" << std::endl;
                        }
                        else
                        {
                            err_state = 1;
                            *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::recv_message::ERROR::No Data received." << std::endl;
                        }
                        receiving = false; // at the moment message can not excceed MAX_DATA_BLOCK_SIZE or more than one DATA_FRAME
                        break;
                    }
                    
                    default:
                        break;
                }
            }
        }

        // returns the length of the filename, > 0 on success
        // -1 on failure
        int recv_filename(char *filename)
        {
            int return_code = -1;
            int recv_val = rcv_data_frame(clientSocket, rcvBuffer);

            if(recv_val > MAX_FILENAME_LENGTH)
            {
                *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::recv_filename::ERROR::Filename too long." << std::endl;
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
                    *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::recv_filename::ERROR::Could not read from frame 0." << std::endl;
            }
            else
            {
                *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::recv_filename::ERROR::Could not retrieve filename." << std::endl;
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
                *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::recv_file::ERROR::Could not get filename." << std::endl;
                return -1;
            }

            std::string path = "";
            path.append(params.outDir);
            if(path[path.size()-1] != *"/") path.append("/");
            path.append(filename);

            const std::filesystem::path filePath{path};
            if(std::filesystem::exists(filePath))
            {
                *global_info.stderrStream << tool::current_time_string() << "::File:" << std::endl;
                *global_info.stderrStream << "File already exists: " << path << "\n" << std::endl;
                return -1;
            }

            DATA_FRAME_HEADER header;
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
            }

            return recv_value;
        }

        void conn_loop()
        {
            int err = 0;
            bool connected = true;

            while(connected)
            {
                switch (state)
                {
                case STATE_RCV_CTRL_FRAME:
                    err = rcv_ctrl_frame();
                    if(err)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::conn_loop::ERROR::Error receiving CTRL_FRAME." << std::endl;
                        err_state = 1;
                        state = STATE_CM_CLOSE_CONN;
                    }
                    else
                        state = STATE_RCV_DATA;
                    break;
                
                case STATE_RCV_DATA:
                    if(type == TYPE_TXT) recv_message();
                    else if(type == TYPE_BIN) recv_file();
                    else if(type == TYPE_NONE)
                    {
                        *global_info.stderrStream << tool::current_time_string() << "::ConnectionManager::conn_loop::ERROR::Type not defined." << std::endl;
                        err_state = 1;
                    }
                    state = STATE_CM_CLOSE_CONN;
                    break;

                case STATE_CM_CLOSE_CONN:
                    close(clientSocket);
                    connected = false;
                    break;
                
                default:
                    break;
                }
            }            
        }

    public:
        ConnectionManager(int sock, Parameter p)
        {
            clientSocket = sock;
            params = p;
            state = STATE_RCV_CTRL_FRAME;
            conn_loop();
        }

        ~ConnectionManager() {}

        int getError() { return err_state; }
};

uint16_t getPort(std::string port_str)
{
    int error = 0;
    uint64_t port = 0;

    try
    {
        port = std::stoul(port_str);
    }
    catch(const std::invalid_argument &e)
    {
        *global_info.stderrStream << "std::invalid_argument::" << e.what() << std::endl;
        *global_info.stderrStream << "Port -p must be a number." << std::endl;
        error = 1;
    }
    catch(const std::out_of_range &e)
    {
        *global_info.stderrStream << "std::out_of_range::" << e.what() << std::endl;
        error = 1;
    }
    if(port > 65535)
    {
        *global_info.stderrStream << "Port can not be greater than 65535." << std::endl;
        error = 1;
    }

    if(error)
    {
        cleanUp();
        exit(1);
    }

    return static_cast<uint16_t>(port);
}

void printHelp()
{
    const char *helpText =
"-i <IPv4>          - IP the server will listen on, if omitted will default to any (0.0.0.0)\n\n\
-p <port>          - TCP port for incoming connections, if omitted defaults to 9009\n\n\
-o <out_folder>    - download folder to store incoming files, if omitted the file will be redirected to stdout\n\
                     incompatible with omitting -m\n\n\
-m <msg_file>      - file to store incoming messages, if omitted messages will be printed to stdout\n\
                     incompatible with omitting -o\n\n\
-e <log_file>      - path to file containing log messages, if omitted errors are redirected to stderr\n\n\
-h                 - print this help\n\n\
-v                 - print version";

    std::cout << helpText << std::endl;
}

void printVersion()
{
    std::cout << "xchange server ver: " << program_version_str << std::endl;
}

void parseArgs(int argc, char* argv[], Parameter &params)
{
    for(int i = 1; i < argc; i++)
    {
        std::string tmp_str = argv[i];

        if( tmp_str == "-i" )
        {
            i++;
            std::string ip_str = argv[i];
            params.ip = tool::ip_from_str(ip_str);
            continue;
        }

        if( tmp_str == "-p" )
        {
            i++;
            std::string port_str = argv[i];
            params.port = getPort(port_str);
            continue;
        }

        if( tmp_str == "-o" )
        {
            i++;
            params.outDir = argv[i];
            continue;
        }

        if( tmp_str == "-m" )
        {
            i++;
            params.msgOutFile = argv[i];
            continue;
        }

        if( tmp_str == "-e" )
        {
            i++;
            params.logFile = argv[i];
            continue;
        }

        if( tmp_str == "-h" )
        {
            params.help = true;
            break;
        }

        if( tmp_str == "-v" )
        {
            params.version = true;
            break;
        }

        *global_info.stderrStream << "Unknown argument: " << tmp_str << std::endl;
        cleanUp();
        exit(1);
    }
}

// check if arguments are coherent/are allowed
int checkArgsPlausibility(Parameter &params)
{
    int err_state = 0;
    
    if(!err_state && params.msgOutFile.size() == 0 && params.outDir.size() == 0)
    {
        *global_info.stderrStream << "Either option -o or -m must be set. xchange will not print files and messages to stdout." << std::endl;
        err_state = 1;
    }

    return err_state;
}

int mainLoop(int serverSocket, Parameter params)
{
    int clientSocket;
    bool serve = true;
    ProgramState state = STATE_WAIT_FOR_CONNECTION;

    while(serve)
    {
        switch (state)
        {
            case STATE_WAIT_FOR_CONNECTION:
            {
                clientSocket = 0;
                clientSocket = accept(serverSocket, nullptr, nullptr);
                if(clientSocket > 0)
                    state = STATE_START_CONN_MANAGER;
                else
                {
                    *global_info.stderrStream << "mainLoop::Error receiving incoming connection." << std::endl;
                }
                break;
            }

            case STATE_START_CONN_MANAGER:
            {
                ConnectionManager conn_manager(clientSocket, params);
                state = STATE_WAIT_FOR_CONNECTION;
                break;
            }

            case STATE_STOP_SERVER:     // placeholder, not in use yet
                break;

            default:
                break;
        }
    }

    return 0;
}

void cleanUp()
{
    close(global_info.serverSocket);
    if(global_info.stdoutStream != &std::cout)
        dynamic_cast<std::ofstream&>(*global_info.stdoutStream).close();
    if(global_info.stderrStream != &std::cerr)
        dynamic_cast<std::ofstream&>(*global_info.stderrStream).close();
}

int main(int argc, char* argv[])
{
    Parameter params;

    //setup CTRL+C handler
    signal(SIGINT, sigint_handler);

    if(argc > 1)
        parseArgs(argc, argv, params);

    if(params.help)
    {
        printHelp();
        return 0;
    }

    if(params.version)
    {
        printVersion();
        return(0);
    }

    int args_err = checkArgsPlausibility(params);
    if(args_err) return 1;

    // defining streams
    std::ofstream out_stream;
    if(params.msgOutFile.size() > 0)
    {
        out_stream.open(params.msgOutFile, std::ofstream::app);
        global_info.stdoutStream = &out_stream;
    }

    std::ofstream err_stream;
    if(params.logFile.size() > 0)
    {
        err_stream.open(params.logFile, std::ofstream::app);
        global_info.stderrStream = &err_stream;
    }

    // create server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(serverSocket < 0)
    {
        *global_info.stderrStream << "main::Error creating socket." << std::endl;
        cleanUp();
        return(1);
    }

    // specifying server address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(params.port);
    serverAddress.sin_addr.s_addr = htonl(params.ip);    // or inet_aton(); inet_addr(const char*)

    // binding socket
    int err = bind(serverSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress));
    if(err)
    {
        *global_info.stderrStream << "main::Error binding socket." << std::endl;
        cleanUp();
        return(1);
    }

    // listening to the assigned socket, up to 0 additional connections/clients for now
    err = listen(serverSocket, 1);
    if(err)
    {
        *global_info.stderrStream << "main::Error setting up server socket to listen at port: " << (int) params.port << std::endl;
        cleanUp();
        return(1);
    }

    int return_code = mainLoop(serverSocket, params);

    cleanUp();

    return return_code;
}
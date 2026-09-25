// implementation of xchange daemon (xcd)
// Todo for ver 0.1.1:
// - implement a dedicated read_from_socket function in ConnectionManager - done
// - log stderr to file - done
// - quota for receive folder
// - setting for max file length

#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "xcd.hpp"
#include "help.hpp"


void sigint_handler(int s)
{
    *global_info.stderrStream << "\rReceived SIGINT, xcd terminated." << std::endl;
    cleanUp();
    exit(0);
}

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
    if(port > MAX_PORT_NBR)
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
    std::cout << xcd_help_text << std::endl;
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

        if( tmp_str == "-kc" )
        {
            i++;
            params.chacha20KeyFile = argv[i];
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

// check if arguments are coherent/allowed
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
                close(clientSocket);
                state = STATE_WAIT_FOR_CONNECTION;
                break;
            }

            case STATE_STOP_SERVER:
                serve = false;
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

    // close log files
    if(global_info.stdoutStream != &std::cout)
        dynamic_cast<std::ofstream&>(*global_info.stdoutStream).close();
    if(global_info.stderrStream != &std::cerr)
        dynamic_cast<std::ofstream&>(*global_info.stderrStream).close();
}

int main(int argc, char* argv[])
{
    Parameter params;

    // ignore SIGPIPE in case writing/write() to broken socket
    signal(SIGPIPE, SIG_IGN);

    // setup CTRL+C handling
    signal(SIGINT, sigint_handler);

    if(argc > 1)
        parseArgs(argc, argv, params);

    // help
    if(params.help)
    {
        printHelp();
        return 0;
    }

    // version
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
        *global_info.stderrStream << "main::Error setting up server socket to listen at port: " << static_cast<int>(params.port) << std::endl;
        cleanUp();
        return(1);
    }

    int error = mainLoop(serverSocket, params);

    // clean up
    cleanUp();

    return error;
}
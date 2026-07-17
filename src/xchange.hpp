#ifndef DEFINITIONS_HPP
#define DEFINITIONS_HPP

#include <ctime>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <sstream>
#include <cstdint>
#include <iostream>

std::string program_version_str = "0.1.0";

/* memory size macros */
#define  B(x)  (x)
#define KB(x) ((x) << 10)
#define MB(x) ((x) << 20)
#define GB(x) ((x) << 30)

enum FLAGS
{
    FLAG_DATA_FRAME = 0x01,
    FLAG_NEW_TRANSMISSION = 0x02,
    FLAG_END_OF_TRANSMISSION = 0x04,
    FLAG_BINARY_TRANSMISSION = 0x08 
};

enum DATA_TYPE
{
    TYPE_TXT,
    TYPE_BIN,
    TYPE_NONE
};

struct CTRL_FRAME
{
    // uint32_t protocol_version = 0x0000;     // not in use yet
    uint8_t flags = 0x00;
    uint8_t transmission_id = 0x00;
};

struct DATA_FRAME_HEADER
{
    uint32_t order_nbr = 0x00;
    uint16_t data_size = 0x00;
    uint8_t flags = 0x00;
    uint8_t transmission_id = 0x00;
    uint8_t chksum = 0x00;
};

typedef uint8_t byte;

const int EOT = -2;                 // defining END-OF-TRANSMISSION

const int TCP_MSS_DEFAULT = 1460;
const int TCP_MSS_JUMBO = 8960;     // at mtu 9000
const int DEFAULT_PORT = 9009;
const int TCP_MSS = TCP_MSS_DEFAULT;

const int MAX_RESEND = 15;
const int MAX_SEND_RETRY_ON_ERR = 3;
const int THREAD_PAUSE_TIME_MS = 50;

const int CTRL_FRAME_SIZE = sizeof(CTRL_FRAME);
const int DATA_FRAME_HEADER_SIZE = sizeof(DATA_FRAME_HEADER);

const int MAX_FILENAME_LENGTH = 128;
const int MAX_DATA_BLOCK_SIZE = TCP_MSS - DATA_FRAME_HEADER_SIZE;    // fit data frame to non-jumbo tcp frame (mtu 1500)
const int MAX_DATA_FRAME_SIZE = DATA_FRAME_HEADER_SIZE + MAX_DATA_BLOCK_SIZE;


namespace tool
{
    uint32_t ip_from_str(const std::string &ip_str)
    {
        uint32_t ip = 0x0;
        std::string token = "";
        std::stringstream ss(ip_str);

        int test_value = 0;
        uint8_t pos = 0;
        while(getline(ss, token, '.'))
        {
            test_value = std::stoul(token);
            if(test_value > 255)
            {
                std::cerr << "Error parsing IPv4 address: " << ip_str << std::endl;
                exit(1);
            }
            else pos = test_value;
            ip <<= 8;
            ip |= pos;
        }
        return ip;
    }

    std::string filename_from_path(const char *path)
    {
        std::string filename = "";
        std::string token = "";
        std::vector<std::string> tokens;
        std::stringstream ss(path);

        while(getline(ss, token, '/')) tokens.push_back(token);
        
        return tokens.back();
    }

    std::string current_time_string()
    {
        size_t buffer_size = 80;
        char buffer[buffer_size];

        std::time_t now = std::time(NULL);
        std::tm *ltm = std::localtime(&now);
        std::strftime(buffer, buffer_size, "%Y-%m-%d_%H:%M:%S", ltm);

        return std::string(buffer);
    }

    uint8_t bufferChkSum(void *buffer, int size)
    {
        uint8_t *bPointer = reinterpret_cast<uint8_t *>(buffer);
        
        int sum = 0;
        for(int i = 0; i < size; i++) sum += bPointer[i];

        uint8_t chk_sum = sum % 255;

        return chk_sum;
    }

    void pauseThread()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_PAUSE_TIME_MS));
    }
}

#endif
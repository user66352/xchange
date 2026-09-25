// TODO:
// - correctly detect early socket removal, might lead write() to report 0 bytes written instead of returning -1

#ifndef DEFINITIONS_HPP
#define DEFINITIONS_HPP

#include <ctime>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>
#include <sstream>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>  // Required for SIOCOUTQ / TIOCOUTQ
#include <errno.h>
#include <poll.h>
#include <unistd.h>

std::string program_version_str = "0.1.4";

/* memory size macros */
#define  B(x)  (x)
#define KB(x) ((x) << 10)
#define MB(x) ((x) << 20)
#define GB(x) ((x) << 30)

typedef uint8_t byte;

enum ACK_ERROR_CODE : uint32_t
{
    ACK_OK,
    ACK_GENERAL_ERR
};

enum FLAGS : uint8_t
{
    FLAG_DATA_FRAME = 0x01,
    FLAG_NEW_TRANSMISSION = 0x02,
    FLAG_END_OF_TRANSMISSION = 0x04,
    FLAG_BINARY_TRANSMISSION = 0x08,
    FLAG_ENCRYPTED = 0x16
};

enum DATA_TYPE
{
    TYPE_NONE,
    TYPE_TXT,
    TYPE_BIN
};

// valid values for PV: PV > PV_NONE || PV < PV_LAST
enum PROTOCOL_VERSION : uint16_t
{
    PV_NONE,
    PV_00_01,       // Default Protocol without encryption
    PV_CHACHA20,    // with CHACHA20 encryption
    PV_XCHACHA20POLY,   // data encrypted with xchacha20 authenticated with poly1305tls
    PV_LAST
};

std::vector<PROTOCOL_VERSION> PROTOCOL_VERSION_VEC =
{
    PV_NONE,
    PV_00_01,
    PV_CHACHA20,
    PV_XCHACHA20POLY,
    PV_LAST
};

// placeholder for later protocol versions supporting auth and encryption
enum SECURITY_VERSION : uint8_t
{
    SV_NONE,
    SV_CHACHA20,
    SV_XCHACHA20POLY,
    SV_LAST
};


//-------------------------------------------------
//------------ FRAME DEFINITIONS BEGIN ------------
//-------------------------------------------------
// all frame structs are packed to make sure they are correctly serialized and de-serialized whene written or read from/to buffer
// might need a dedicated serialize/deserialize function for compatibility between different architectures / to guarantee correct reconstruction from buffer

struct __attribute__((__packed__)) CTRL_FRAME
{
    PROTOCOL_VERSION pv = PV_NONE;
    SECURITY_VERSION sv = SV_NONE;
    uint8_t flags = 0x00;
    uint8_t transmission_id = 0x00;     // arbitrary number that MUST be the same for all packets belonging to the same stream
};

struct __attribute__((__packed__)) DATA_FRAME_HEADER
{
    uint32_t order_nbr = 0x00;          // order of packet within the stream
    uint16_t data_size = 0x00;          // count of data bytes within this packet
    uint8_t flags = 0x00;
    uint8_t transmission_id = 0x00;     // same as ctrl_frame transmission_id
    uint8_t chksum = 0x00;              // checksum of data payload
};

struct __attribute__((__packed__)) ACK_FRAME
{
    const char ack[4] = {'A', 'C', 'K', '\0'};
    ACK_ERROR_CODE error = ACK_GENERAL_ERR;
};

//-----------------------------------------------
//------------ FRAME DEFINITIONS END ------------
//-----------------------------------------------


struct XCD_GLOBAL_INFO
{
    std::ostream *stdoutStream = &std::cout;    // &std::cout; path to where received messages or files printed
    std::ostream *stderrStream = &std::cerr;    // &std::cerr
    std::string outDir = "";
    uint64_t maxFileLength = 0;
    uint64_t downloadFolderQuota = 0;
    int serverSocket = 0;
    bool filesToStdout = false;                 // if true received files redirected to stdoutStream
} global_info;

PROTOCOL_VERSION PV_DEFAULT = PV_00_01;         // default protocol version to use in case version was not specified by user (default is plain text)

const int EOT = -2;                 // END-OF-TRANSMISSION

const int BUCKETS_PER_SEC = 5;      // buckets per sec for bandwidth control
const int TCP_MSS_NORMAL = 1460;    // default
const int TCP_MSS_JUMBO = 8960;     // at mtu 9000
const int DEFAULT_PORT = 9009;
const int MAX_PORT_NBR = 65535;
const int MSS = TCP_MSS_NORMAL;

const int MAX_RESEND = 15;
const int MAX_SEND_RETRY_ON_ERR = 3;
const int MAX_READ_RETRY_ON_ERR = 3;
const int THREAD_PAUSE_TIME_MS = 50;

const int ACK_FRAME_SIZE = sizeof(ACK_FRAME);
const int CTRL_FRAME_SIZE = sizeof(CTRL_FRAME);
const int DATA_FRAME_HEADER_SIZE = sizeof(DATA_FRAME_HEADER);

const int MAX_FILENAME_LENGTH = 128;
const int MAX_DATA_BLOCK_SIZE = MSS - DATA_FRAME_HEADER_SIZE;                   // fit data frame to non-jumbo tcp frame (mtu 1500), max user data bytes per frame
const int MAX_DATA_FRAME_SIZE = DATA_FRAME_HEADER_SIZE + MAX_DATA_BLOCK_SIZE;   // max bytes send at once as one; considered a frame (meta data/header + user data)


//----------------------------------------
//------------ TIMING OPTIONS ------------
//----------------------------------------

const time_t SOCKET_RCVTIMEO_SEC = 5;
const time_t SOCKET_SNDTIMEO_SEC = 5;
const int64_t XCD_CONFIRM_WAIT_MICROS = 5 * 1000000; // 5 sec


//-----------------------------------------------------
//------------ HELPER AND SHARED FUNCTIONS ------------
//-----------------------------------------------------

namespace tool
{
    // takes a pointer to a buffer, returns a hex string of buffer values
    // upperLower controls the case [u:upper, l:lower]
    // returns a string of hex values coresponding to the bytes from buffer
    std::string byteToHex(void *buffer, int length, char upperLower)
    {
        std::string res;
        char val;
        byte mask = 0x0f, low, high;

        char *lookup_table;
        char lookup_table_upper[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char lookup_table_lower[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        if(upperLower == 'l') lookup_table = lookup_table_lower;
        if(upperLower == 'u') lookup_table = lookup_table_upper;

        byte *byte_arr = static_cast<byte *>(buffer);

        for(int i = 0; i < length; i++)
        {
            val = byte_arr[i];
            low = val & mask;
            val >>= 4;
            high = val & mask;
            res.push_back(lookup_table[high]);
            res.push_back(lookup_table[low]);
        }

        return res;
    }

    // buffer size assumed at least as string.size() / 2
    // return amount of bytes converted
    int hexToByte(std::string hexString, void *buffer)
    {
        int byte_counter = 0;
        int length = hexString.size();
        char low, high;
        char *byte_arr = static_cast<char *>(buffer);

        for(int i = 0; i < length; i += 2)
        {
            // convert high nibbl
            if(hexString[i] < ':')
            {
                high = hexString[i] - '0';
            }
            else
            {
                high = hexString[i] - 'W';
            }

            // convert low nibble
            int j = i + 1;
            if(hexString[j] < ':')
            {
                low = hexString[j] - '0';
            }
            else
            {
                low = hexString[j] - 'W';
            }

            byte_arr[byte_counter] = high;
            byte_arr[byte_counter] <<= 4;
            byte_arr[byte_counter] += low;

            byte_counter++;
        }

        return byte_counter;
    }

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
                #ifdef CLIENT
                std::cerr << "Error parsing IPv4 address: " << ip_str << std::endl;
                #endif

                #ifdef SERVER
                *global_info.stderrStream << "Error parsing IPv4 address: " << ip_str << std::endl;
                #endif

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
        const size_t buffer_size = 80;
        char buffer[buffer_size];

        std::time_t now = std::time(NULL);
        std::tm *ltm = std::localtime(&now);
        std::strftime(buffer, buffer_size, "%Y-%m-%d_%H:%M:%S", ltm);

        return std::string(buffer);
    }

    uint8_t bufferChkSum(void *buffer, int size)
    {
        uint8_t *bPointer = reinterpret_cast<uint8_t *>(buffer);
        
        uint32_t sum = 0;
        for(int i = 0; i < size; i++) sum += bPointer[i];

        uint8_t chk_sum = sum % 255;

        return chk_sum;
    }

    // create fletcher16 chksum of data_buffer
    uint16_t fletcher16(const uint8_t *data, size_t len) {
        uint32_t c0, c1;
        size_t blocklen;
        
        for (c0 = c1 = 0; len > 0; ) {
            blocklen = len;
            if (blocklen > 5802) {
                blocklen = 5802;
            }
            len -= blocklen;
            do {
                c0 = c0 + *data++;
                c1 = c1 + c0;
            } while (--blocklen);
            c0 = c0 % 255;
            c1 = c1 % 255;
    }
    return (c1 << 8 | c0);
    }

    // pause thread for THREAD_PAUSE_TIME_MS
    void pauseThread()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_PAUSE_TIME_MS));
    }

    // sleeps for the given amount of µs
    void sleep(int64_t microSec)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(microSec));
    }
}

namespace sio
{
    int getWriteSocketQueueSize(int sock)
    {
        int total_queue_size = 0;
        socklen_t optlen = sizeof(total_queue_size);

        // get total allocated send buffer size
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
        // cast buffer into write accepted type
        const char *buffer = const_cast<const char *>(static_cast<char *>(buff));

        // determine the socket queue length
        size_t socket_queue_length = getWriteSocketQueueSize(sock);
        if(socket_queue_length < 0)
        {
            std::cerr << "write_to_socket error" << std::endl;
            int err = errno;
            const char *errName = strerrorname_np(err);
            const char *errDesc = strerrordesc_np(err);

            #ifdef CLIENT
            std::cerr << "\nwrite_to_socket::ERROR::Error at getting queue length (" << errName << ")\n";
            std::cerr << "write_to_socket::ERROR::" << errDesc << std::endl;
            #endif

            #ifdef SERVER
            *global_info.stderrStream << "\nwrite_to_socket::ERROR::Error at getting queue length (" << errName << ")\n";
            *global_info.stderrStream << "write_to_socket::ERROR::" << errDesc << std::endl;
            #endif

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
                #ifdef CLIENT
                std::cerr << "write_to_socket::ERROR::maximum retry_on_err count exceeded" << std::endl;
                #endif

                #ifdef SERVER
                *global_info.stderrStream << "write_to_socket::ERROR::maximum retry_on_err count exceeded" << std::endl;
                #endif

                return -1;
            }

            if(resend_count > MAX_RESEND)
            {
                #ifdef CLIENT
                std::cerr << "write_to_socket::ERROR::maximum resend attempts exceeded" << std::endl;
                #endif

                #ifdef SERVER
                *global_info.stderrStream << "write_to_socket::ERROR::maximum resend attempts exceeded" << std::endl;
                #endif

                return -1;
            }

            if(bytes_remaining >= write_at_once)
                bytes_to_send = write_at_once;
            else
                bytes_to_send = bytes_remaining;

            ret_val = write(sock, &buffer[bytes_sent], bytes_to_send);
            if(ret_val < 0)
            {
                std::cerr << "write_to_socket error" << std::endl;
                int err = errno;
                const char *errName = strerrorname_np(err);
                const char *errDesc = strerrordesc_np(err);

                #ifdef CLIENT
                std::cerr << "\nwrite_to_socket::ERROR::write returned with error: " << errName << "\n";
                std::cerr << "write_to_socket::ERROR::" << errDesc << std::endl;
                #endif

                #ifdef SERVER
                *global_info.stderrStream << "\nwrite_to_socket::ERROR::write returned with error: " << errName << "\n";
                *global_info.stderrStream << "write_to_socket::ERROR::" << errDesc << std::endl;
                #endif

                if(err == EAGAIN || err == EWOULDBLOCK || err == EINTR)
                {
                    std::cerr << "write_to_socket error" << std::endl;
                    tool::pauseThread();
                    retry_count_err++;

                    #ifdef CLIENT
                    std::cerr << "write_to_socket::WARNING::retry_on_err count: " << retry_count_err << std::endl;
                    #endif

                    #ifdef SERVER
                    *global_info.stderrStream << "write_to_socket::WARNING::retry_on_err count: " << retry_count_err << std::endl;
                    #endif

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
            
            if(bytes_remaining == 0) active = false;

            resend_count++;
        }
        return 0;
    }

    // returns 0 on success and -1 on error
    int read_from_socket(int sock, void *buff, size_t bufferSize, int flags)
    {
        int ret_value = 0;
        int retry_counter = (1000 / THREAD_PAUSE_TIME_MS) * SOCKET_RCVTIMEO_SEC;    // recv retries timeout
        size_t remaining_bytes = bufferSize;

        while(remaining_bytes > 0)
        {
            ret_value = recv(sock, buff, remaining_bytes, flags);
            if(ret_value < 0)
            {
                int err = errno;
                if((err == EAGAIN) || (err = EWOULDBLOCK) || (err == EINTR))
                {
                    retry_counter++;
                    if(retry_counter > MAX_READ_RETRY_ON_ERR)
                    {
                        const char *errName = strerrorname_np(err);
                        const char *errDesc = strerrordesc_np(err);

                        int bytesAv = 0;
                        ioctl(sock, FIONREAD, bytesAv);

                        #ifdef SERVER
                        *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::ERROR::Read retry exceeded: (" << errName << ")\n";
                        *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::ERROR::" << errDesc << std::endl;
                        *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::INFO:: Bytes available in sock: " << bytesAv << std::endl;
                        #endif

                        #ifdef CLIENT
                        std::cerr << "sio::read_from_socket::ERROR::Read retry exceeded: (" << errName << ")\n";
                        std::cerr << "sio::read_from_socket::ERROR::" << errDesc << std::endl;
                        #endif

                        return -1;
                    }
                    tool::pauseThread();
                }
                else
                {
                    const char *errName = strerrorname_np(err);
                    const char *errDesc = strerrordesc_np(err);

                    int bytesAv = 0;
                    ioctl(sock, FIONREAD, bytesAv);
                    
                    #ifdef SERVER
                    *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::ERROR::Error reading from socket: (" << errName << ")\n";
                    *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::ERROR::" << errDesc << std::endl;
                    *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::INFO:: Bytes available in sock: " << bytesAv << std::endl;
                    #endif

                    #ifdef CLIENT
                    std::cerr << "sio::read_from_socket::ERROR::Error reading from socket: (" << errName << ")\n";
                    std::cerr << "sio::read_from_socket::ERROR::" << errDesc << std::endl;
                    #endif

                    return -1;
                }
            }
            remaining_bytes -= ret_value;

            // make sure recv times out after SOCKET_RCVTIMEO_SEC if nothing is received
            if(remaining_bytes > 0 && ret_value == 0)
            {
                retry_counter--;
                tool::pauseThread();
            }
            if(!retry_counter)
            {
                    #ifdef SERVER
                    *global_info.stderrStream << tool::current_time_string() << "::sio::read_from_socket::ERROR::recv timeout exceeded." << std::endl;
                    #endif

                    #ifdef CLIENT
                    std::cerr << "sio::read_from_socket::ERROR::recv timeout exceeded." << std::endl;
                    #endif

                    return -1;
            }
        }
        return 0;
    }
}

#endif
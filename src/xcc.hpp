#ifndef XCC_HPP
#define XCC_HPP

#include "xchange.hpp"

enum TransferMode
{
    MODE_TEXT,
    MODE_FILE,
    MODE_NONE
};

struct TransferInfo
{
    int clientSocket = 0;
    const char *msg = nullptr;
    const char *filePath = nullptr;
    std::string keyFile = "";
    SECURITY_VERSION secVer = SV_NONE;
    TransferMode mode = MODE_NONE;
    uint64_t bandwidth = 0;
    byte TransmissionID = 0x00;
    bool stats = false;
};


class ControlFrame
{
    private:
        CTRL_FRAME frame_intern, frame_extern;

        void resetCtrlFrame() { frame_intern = { .pv = PV_NONE, .flags = 0x00, .transmission_id = 0x00 }; }

    public:
        ControlFrame()
        {
            resetCtrlFrame();
        }


        void setFlag(byte flag) { frame_intern.flags |= flag; }

        void setTransmissionID(byte id) { frame_intern.transmission_id = id; }

        void setProtocolVer(PROTOCOL_VERSION pv) { frame_intern.pv = pv; }

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
        char *dataPointer = nullptr;
        char transmitBuffer[DATA_FRAME_HEADER_SIZE + MAX_DATA_BLOCK_SIZE] = { 0 };
        DATA_FRAME_HEADER header;

        void setChkSum()
        {
            // char *bufferPointer = const_cast<char *>(dataPointer);
            // header.chksum = tool::bufferChkSum(bufferPointer, header.data_size);
            header.chksum = tool::bufferChkSum(dataPointer, header.data_size);
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
            dataPointer = nullptr;
        }

    public:
        void setFlag(byte flag) { header.flags |= flag; }
        
        void setTransmissionID(byte id) { header.transmission_id = id; }

        void setOrder(uint32_t nbr) { header.order_nbr = nbr; }

        void setData(void *data, uint16_t size)
        {
            dataPointer = static_cast<char *>(data);
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

#endif
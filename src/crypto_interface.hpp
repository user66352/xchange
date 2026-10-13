#ifndef CRYPTO_INTERFACE_HPP
#define CRYPTO_INTERFACE_HPP

#include <crypto++/cryptlib.h>

class EncryptionInterface {
    public:
        EncryptionInterface() = default;
        virtual ~EncryptionInterface() = default;
        virtual std::string getCipherName() = 0;
        virtual CryptoPP::byte *getIV() = 0;
        virtual int getIVSize() = 0;
        virtual int getKeySize() = 0;
        virtual int getDataBlockSize() = 0;
        virtual int getDataFrameSize() = 0;
        virtual int readKey(std::string keyFile) = 0;
        virtual void setKey(void *buff) = 0;
        virtual int encrypt(void *inBuffer, void* outBuffer, size_t length) = 0;
};

class DecryptionInterface {
    public:
        virtual ~DecryptionInterface() = default;
        virtual std::string getCipherName() = 0;
        virtual int getIVSize() = 0;
        virtual int getKeySize() = 0;
        virtual int getDataBlockSize() = 0;
        virtual int getDataFrameSize() = 0;
        virtual int getMacSize() = 0;
        virtual int readKey(std::string keyFile) = 0;
        virtual void setIV(void *nonce) = 0;
        virtual void setKey(void *buff) = 0;
        virtual bool decrypt(void *inBuffer, void* outBuffer, size_t length) = 0;
};

#endif
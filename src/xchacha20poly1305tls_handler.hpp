#ifndef XCHACHA20POLY1305TLS_HPP
#define XCHACHA20POLY1305TLS_HPP

#include <string.h>
#include <fstream>

#include <crypto++/chachapoly.h>
#include <crypto++/osrng.h>
#include <crypto++/hkdf.h>
#include <crypto++/sha.h>

#include "crypto_interface.hpp"

const int POLY1305_MAC_SIZE = CryptoPP::Poly1305TLS::DIGESTSIZE; // 16
const int XCHACHA20_IV_SIZE = CryptoPP::XChaCha20::IV_LENGTH;   // 24
const int XCHACHA20_KEY_SIZE = CryptoPP::XChaCha20::KEYLENGTH;  // 32
const int MAX_DATA_BYTE_PER_FRAME_XPOLY = MAX_DATA_BLOCK_SIZE - POLY1305_MAC_SIZE;
const int DATA_FRAME_SIZE_XCHA_POLY = MAX_DATA_FRAME_SIZE - POLY1305_MAC_SIZE;

/*
 ****************************
 ***** Shared Functions *****
 ****************************
 */

NAMESPACE_BEGIN(XChaLocal)

void incrementIV(CryptoPP::byte *numArr, size_t size)
{
    for(int i = 0; i < size; i++)
    {
        numArr[i]++;
        if(numArr[i] != 0) break;
    }
}

// reads 32 byte into key array from file, requires a 32 byte key file
// returns 0 on success, 1 on failure
int readXChaCha20Key(std::string keyFile, void *buffer)
{
    return tool::readBinaryKey(keyFile, buffer, XCHACHA20_KEY_SIZE);
}

void deriveKey(void *ikm, int ikmLength, CryptoPP::byte *salt, int saltLength, CryptoPP::byte *key, int keyLength)
{
    CryptoPP::byte *ikmPointer = static_cast<CryptoPP::byte *>(ikm);

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, keyLength, ikmPointer, ikmLength, salt, saltLength, NULL, 0);
}

NAMESPACE_END


class XChaCha20Poly1305_Encrypt : public EncryptionInterface
{
    private:
        CryptoPP::byte iv[XCHACHA20_IV_SIZE];
        CryptoPP::byte key[XCHACHA20_KEY_SIZE];
        CryptoPP::byte sessionKey[XCHACHA20_KEY_SIZE];
        CryptoPP::XChaCha20Poly1305::Encryption enc;
        CryptoPP::AutoSeededRandomPool rng;

        void initIV()
        {
            rng.GenerateBlock(iv, XCHACHA20_IV_SIZE);
        }

    public:
        XChaCha20Poly1305_Encrypt()
        {
            memset(iv, 0, XCHACHA20_IV_SIZE);
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
            initIV();
        }

        ~XChaCha20Poly1305_Encrypt()
        {
            memset(key, 0x00, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0x00, XCHACHA20_KEY_SIZE);
        }

        std::string getCipherName() override { return std::string("XCHACHA20_POLY1305"); }

        CryptoPP::byte *getIV() override { return iv; }

        int getKeySize() override {return XCHACHA20_KEY_SIZE; }

        int getIVSize() override { return XCHACHA20_IV_SIZE; }

        int getDataBlockSize() override { return MAX_DATA_BYTE_PER_FRAME_XPOLY; }

        int getDataFrameSize() override { return DATA_FRAME_SIZE_XCHA_POLY; }


        // read 32byte key file and create session key
        int readKey(std::string keyFile) override
        {
            int ret = XChaLocal::readXChaCha20Key(keyFile, key);

            // create session key
            deriveKey(key, XCHACHA20_KEY_SIZE, iv, XCHACHA20_IV_SIZE, sessionKey, XCHACHA20_KEY_SIZE);

            return ret;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);
        }

        // inBuffer  - plain data
        // outBuffer - buffer receiving the encrypted data + mac
        // length    - amount of bytes to encrypt
        // return the size of encrypted data + mac
        // return 0 on failure
        int encrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            CryptoPP::byte mac[POLY1305_MAC_SIZE] = {0};
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            if(length > DATA_FRAME_SIZE_XCHA_POLY)     // make sure there is space left for the poly1305 MAC
            {
                std::cerr << "xchacha20poly1305tls_handler.hpp::XChaCha20Poly1305TLS_Encrypt::encrypt::Data length too large. No space to add MAC." << std::endl;
                std::cerr << "xchacha20poly1305tls_handler.hpp::XChaCha20Poly1305TLS_Encrypt::encrypt::frame length: " << length << std::endl;
                return 0;
            }

            // add padding to frame if data block is not completely filled
            int paddingSize = DATA_FRAME_SIZE_XCHA_POLY - length;
            if(paddingSize) rng.GenerateBlock(&in[length] , paddingSize);

            XChaLocal::incrementIV(iv, XCHACHA20_IV_SIZE);

            // encrypt data
            enc.SetKeyWithIV(sessionKey, XCHACHA20_KEY_SIZE, iv);
            enc.EncryptAndAuthenticate(out, mac, POLY1305_MAC_LENGTH, iv, XCHACHA20_IV_SIZE, NULL, 0, in, DATA_FRAME_SIZE_XCHA_POLY);

            // append MAC to out buffer
            memcpy(&out[DATA_FRAME_SIZE_XCHA_POLY], mac, POLY1305_MAC_SIZE);

            return DATA_FRAME_SIZE_XCHA_POLY + POLY1305_MAC_SIZE;
        }
};

class XChaCha20Poly1305_Decrypt : public DecryptionInterface
{
    private:
        CryptoPP::byte iv[XCHACHA20_IV_SIZE];
        CryptoPP::byte key[XCHACHA20_KEY_SIZE];
        CryptoPP::byte sessionKey[XCHACHA20_KEY_SIZE];
        CryptoPP::XChaCha20Poly1305::Decryption dec;

    public:
        XChaCha20Poly1305_Decrypt()
        {
            memset(iv, 0, XCHACHA20_IV_SIZE);
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
        }

        ~XChaCha20Poly1305_Decrypt()
        {
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
        }

        std::string getCipherName() override { return std::string("XCHACHA20_POLY1305"); }

        int getKeySize() override {return XCHACHA20_KEY_SIZE; }

        int getIVSize() override { return XCHACHA20_IV_SIZE; }

        int getDataBlockSize() override { return MAX_DATA_BYTE_PER_FRAME_XPOLY; }

        int getDataFrameSize() override { return DATA_FRAME_SIZE_XCHA_POLY; }

        int getMacSize() override { return POLY1305_MAC_SIZE; }
        

        void setIV(void *nonce) override
        {
            memcpy(iv, nonce, XCHACHA20_IV_SIZE);
        }

        // read 32byte key file and create session key
        int readKey(std::string keyFile) override
        {
            int ret = XChaLocal::readXChaCha20Key(keyFile, key);

            // create session key
            deriveKey(key, XCHACHA20_KEY_SIZE, iv, XCHACHA20_IV_SIZE, sessionKey, XCHACHA20_KEY_SIZE);

            return ret;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);
        }

        // inBuffer  - encrypted data (entire frame including mac)
        // outBuffer - buffer receiving the plain data
        // length    - frame length in inBuffer | frame/inBuffer: [data+mac[POLY1305TLS_MAC_SIZE]]
        // returns 1 on success (authenticated), 0 when mac authentication has failed
        bool decrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);
            CryptoPP::byte *mac = static_cast<CryptoPP::byte *>(&in[DATA_FRAME_SIZE_XCHA_POLY]);

            XChaLocal::incrementIV(iv, XCHACHA20_IV_SIZE);

            dec.SetKeyWithIV(sessionKey, XCHACHA20_KEY_SIZE, iv);
            bool verified = dec.DecryptAndVerify(out, mac, POLY1305_MAC_LENGTH, iv, XCHACHA20_IV_SIZE, NULL, 0, in, DATA_FRAME_SIZE_XCHA_POLY);

            if(!verified)
            {
                *global_info.stderrStream << tool::current_time_string() << "::XChaCha20Poly1305_handler::decrypt::ERROR::MAC authentication failed." << std::endl;
            }

            return verified;
        }
};

#endif
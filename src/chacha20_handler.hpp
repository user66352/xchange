#ifndef CHACHA20_HANDLER_HPP
#define CHACHA20_HANDLER_HPP

#include <crypto++/chachapoly.h>
#include <crypto++/osrng.h>
#include <crypto++/hkdf.h>
#include <crypto++/sha.h>

#include "crypto_interface.hpp"


const int POLY1305_MAC_LENGTH = 16;
const int CHACHA20_IV_LENGTH = 12;
const int CHACHA20_KEY_LENGTH = 32;
const int CHACHAPOLY_DATA_FRAME_SIZE = MAX_DATA_FRAME_SIZE - POLY1305_MAC_LENGTH;           // data_frame header + payload
const int CHACHAPOLY_DATA_BLOCK_SIZE = CHACHAPOLY_DATA_FRAME_SIZE - DATA_FRAME_HEADER_SIZE; // data payload inside data_frame


void incrementIV(CryptoPP::byte *numArr, size_t size);
void deriveKey(void *ikm, int ikmLength, CryptoPP::byte *salt, int saltLength, CryptoPP::byte *key, int keyLength);

class ChaCha20_Decrypt : public DecryptionInterface
{
    private:
        CryptoPP::byte iv[CHACHA20_IV_LENGTH];
        CryptoPP::byte key[CHACHA20_KEY_LENGTH];
        CryptoPP::byte sessionKey[CHACHA20_KEY_LENGTH];
        CryptoPP::ChaCha20Poly1305::Decryption dec;

    public:
        ChaCha20_Decrypt() {}

        ~ChaCha20_Decrypt()
        {
            memset(key, 0x00, CHACHA20_KEY_LENGTH);
            memset(sessionKey, 0x00, CHACHA20_KEY_LENGTH);
        }

        std::string getCipherName() override { return std::string("CHACHA20_POLY1305"); }

        int getIVSize() override { return CHACHA20_IV_LENGTH; }

        int getKeySize() override { return CHACHA20_KEY_LENGTH; }

        int getDataBlockSize() override { return CHACHAPOLY_DATA_BLOCK_SIZE; }

        int getDataFrameSize() override { return CHACHAPOLY_DATA_FRAME_SIZE; }

        int getMacSize() override { return POLY1305_MAC_LENGTH; }


        void setIV(void *nonce) override
        {
            memcpy(iv, nonce, CHACHA20_IV_LENGTH);
        }

        // read 32byte from key file
        int readKey(std::string keyFile) override
        {
            int err = tool::readBinaryKey(keyFile, key, CHACHA20_KEY_LENGTH);

            // create session key
            if(!err)
                deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);

            return err;
        }

        // expects a 32byte buffer filled with the new key
        void setKey(void *buff) override
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);
        }

        // in buffer to read from, out buffer to write/decrypt to
        // length: total frame size including mac
        // return true if verified, false if not verified
        bool decrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            int frame_length = length - POLY1305_MAC_LENGTH;

            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);
            CryptoPP::byte *mac = static_cast<CryptoPP::byte *>(&in[frame_length]);

            incrementIV(iv, CHACHA20_IV_LENGTH);

            dec.SetKeyWithIV(sessionKey, CHACHA20_KEY_LENGTH, iv);
            return dec.DecryptAndVerify(out, mac, POLY1305_MAC_LENGTH, iv, CHACHA20_IV_LENGTH, NULL, 0, in, frame_length);
        }
};

class ChaCha20_Encrypt : public EncryptionInterface
{
    private:
        CryptoPP::byte iv[CHACHA20_IV_LENGTH];
        CryptoPP::byte key[CHACHA20_KEY_LENGTH];
        CryptoPP::byte mac[POLY1305_MAC_LENGTH];
        CryptoPP::byte sessionKey[CHACHA20_KEY_LENGTH];
        CryptoPP::ChaCha20Poly1305::Encryption enc;
        CryptoPP::AutoSeededRandomPool rng;

        void initIV()
        {
            rng.GenerateBlock(iv, CHACHA20_IV_LENGTH);
        }

    public:
        ChaCha20_Encrypt()
        {
            initIV();
        }

        ~ChaCha20_Encrypt()
        {
            memset(key, 0x00, CHACHA20_KEY_LENGTH);
            memset(sessionKey, 0x00, CHACHA20_KEY_LENGTH);
        }

        std::string getCipherName() override { return std::string("CHACHA20_POLY1305"); }

        CryptoPP::byte *getIV() override { return iv; }

        int getIVSize() override { return CHACHA20_IV_LENGTH; }

        int getKeySize() override { return CHACHA20_KEY_LENGTH; }

        int getDataBlockSize() override { return CHACHAPOLY_DATA_BLOCK_SIZE; }

        int getDataFrameSize() override { return CHACHAPOLY_DATA_FRAME_SIZE; }


        // reads a binary key file and creates a session key from it
        // returns 0 on success; 1 on failure
        int readKey(std::string keyFile) override
        {
            int err = tool::readBinaryKey(keyFile, key, CHACHA20_KEY_LENGTH);

            // create session key
            if(!err)
                deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);

            return err;
        }

        // expects a 32byte buffer filled with the new key
        void setKey(void *buff) override
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            deriveKey(key, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH, sessionKey, CHACHA20_KEY_LENGTH);
        }

        // length: data frame size in inBuffer (header + data <= CHACHAPOLY_DATA_FRAME_SIZE)
        int encrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            // add padding to frame if not completely filled
            int paddingSize = CHACHAPOLY_DATA_FRAME_SIZE - length;
            if(paddingSize)
                rng.GenerateBlock(&in[length] , paddingSize);

            incrementIV(iv, CHACHA20_IV_LENGTH);

            // encrypt data
            enc.SetKeyWithIV(sessionKey, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH);
            enc.EncryptAndAuthenticate(out, mac, POLY1305_MAC_LENGTH, iv, CHACHA20_IV_LENGTH, NULL, 0, in, CHACHAPOLY_DATA_FRAME_SIZE);

            // add MAC to out buffer
            memcpy(&out[CHACHAPOLY_DATA_FRAME_SIZE], mac, POLY1305_MAC_LENGTH);

            return CHACHAPOLY_DATA_FRAME_SIZE + POLY1305_MAC_LENGTH;
        }
};


/*
 ********************
 * Shared Functions *
 ********************
*/

void deriveKey(void *ikm, int ikmLength, CryptoPP::byte *salt, int saltLength, CryptoPP::byte *key, int keyLength)
{
    CryptoPP::byte *ikmPointer = static_cast<CryptoPP::byte *>(ikm);

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, keyLength, ikmPointer, ikmLength, salt, saltLength, NULL, 0);
}

void incrementIV(CryptoPP::byte *numArr, size_t size)
{
    for(int i = 0; i < size; i++)
    {
        numArr[i]++;
        if(numArr[i] != 0) break;
    }
}

#endif
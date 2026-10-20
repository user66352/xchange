#ifndef AES_GCM_HANDLER
#define AES_GCM_HANDLER

#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/osrng.h>
#include <crypto++/hkdf.h>
#include <crypto++/sha.h>

#include "xchange.hpp"
#include "crypto_interface.hpp"

const int AES_GCM_KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH;
const int AES_GCM_IV_SIZE = 12;
const int AES_GCM_MAC_SIZE = 16;
const int MAX_DATA_BLOCK_SIZE_AES_GCM = MAX_DATA_BLOCK_SIZE - AES_GCM_MAC_SIZE;
const int MAX_DATA_FRAME_SIZE_AES_GCM = MAX_DATA_FRAME_SIZE - AES_GCM_MAC_SIZE;


NAMESPACE_BEGIN(AESLocal)

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
int readAESKey(std::string keyFile, void *buffer)
{
    return tool::readBinaryKey(keyFile, buffer, AES_GCM_KEY_SIZE);
}

void deriveKey(void *ikm, int ikmLength, CryptoPP::byte *salt, int saltLength, CryptoPP::byte *key, int keyLength)
{
    CryptoPP::byte *ikmPointer = static_cast<CryptoPP::byte *>(ikm);

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, keyLength, ikmPointer, ikmLength, salt, saltLength, NULL, 0);
}

NAMESPACE_END


class AES_GCM_Encrypt : public EncryptionInterface
{
    private:
        CryptoPP::byte iv[AES_GCM_IV_SIZE];
        CryptoPP::byte key[AES_GCM_KEY_SIZE];
        CryptoPP::byte sessionKey[AES_GCM_KEY_SIZE];
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        CryptoPP::AutoSeededRandomPool rng;

        void initIV()
        {
            rng.GenerateBlock(iv, AES_GCM_IV_SIZE);
        }

    public:
        AES_GCM_Encrypt() {
            memset(iv, 0, AES_GCM_IV_SIZE);
            memset(key, 0, AES_GCM_KEY_SIZE);
            memset(sessionKey, 0, AES_GCM_KEY_SIZE);
            initIV();
        }

        ~AES_GCM_Encrypt() {
            memset(key, 0x00, AES_GCM_KEY_SIZE);
            memset(sessionKey, 0x00, AES_GCM_KEY_SIZE);
        }

        std::string getCipherName() override { return std::string("AES_GCM"); }

        CryptoPP::byte *getIV() override { return iv; }

        int getKeySize() override {return AES_GCM_KEY_SIZE; }

        int getIVSize() override { return AES_GCM_IV_SIZE; }

        int getDataBlockSize() override { return MAX_DATA_BLOCK_SIZE_AES_GCM; }

        int getDataFrameSize() override { return MAX_DATA_FRAME_SIZE_AES_GCM; }

        // read 32byte key file and create session key
        int readKey(std::string keyFile) override
        {
            int ret = AESLocal::readAESKey(keyFile, key);

            // create session key
            AESLocal::deriveKey(key, AES_GCM_KEY_SIZE, iv, AES_GCM_IV_SIZE, sessionKey, AES_GCM_KEY_SIZE);

            return ret;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, AES_GCM_KEY_SIZE);

            // create session key
            AESLocal::deriveKey(key, AES_GCM_KEY_SIZE, iv, AES_GCM_IV_SIZE, sessionKey, AES_GCM_KEY_SIZE);
        }

        // inBuffer  - plain data
        // outBuffer - buffer receiving the encrypted data + mac
        // length    - amount of bytes to encrypt, typically an entire data frame (header + payload data)
        // return the size of encrypted data + mac
        // return 0 on failure
        int encrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            CryptoPP::byte mac[AES_GCM_MAC_SIZE] = {0};
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            if(length > MAX_DATA_FRAME_SIZE_AES_GCM)     // make sure there is space left for the GCM MAC
            {
                std::cerr << "aes_gcm_handler.hpp::AES_GCM_Encrypt::encrypt::Data length too large. No space to add MAC." << std::endl;
                std::cerr << "aes_gcm_handler.hpp::AES_GCM_Encrypt::encrypt::frame length: " << length << std::endl;
                return 0;
            }

            // add padding to frame if data block is not completely filled
            int paddingSize = MAX_DATA_FRAME_SIZE_AES_GCM - length;
            if(paddingSize) rng.GenerateBlock(&in[length] , paddingSize);

            AESLocal::incrementIV(iv, AES_GCM_IV_SIZE);

            // encrypt data
            enc.SetKeyWithIV( sessionKey, AES_GCM_KEY_SIZE, iv );
            enc.EncryptAndAuthenticate( out, mac, AES_GCM_MAC_SIZE, iv, AES_GCM_IV_SIZE, NULL, 0, in, MAX_DATA_FRAME_SIZE_AES_GCM );

            // append MAC to out buffer
            memcpy(&out[MAX_DATA_FRAME_SIZE_AES_GCM], mac, AES_GCM_MAC_SIZE);

            return MAX_DATA_FRAME_SIZE_AES_GCM + AES_GCM_MAC_SIZE;
        }
};


class AES_GCM_Decrypt : public DecryptionInterface
{
    private:
        CryptoPP::byte iv[AES_GCM_IV_SIZE];
        CryptoPP::byte key[AES_GCM_KEY_SIZE];
        CryptoPP::byte sessionKey[AES_GCM_KEY_SIZE];
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;

    public:
        AES_GCM_Decrypt() {
            memset(iv, 0, AES_GCM_IV_SIZE);
            memset(key, 0, AES_GCM_KEY_SIZE);
            memset(sessionKey, 0, AES_GCM_KEY_SIZE);
        }

        ~AES_GCM_Decrypt() {
            memset(key, 0, AES_GCM_KEY_SIZE);
            memset(sessionKey, 0, AES_GCM_KEY_SIZE);
        }

        std::string getCipherName() override { return std::string("AES_GCM"); }

        int getKeySize() override {return AES_GCM_KEY_SIZE; }

        int getIVSize() override { return AES_GCM_IV_SIZE; }

        int getDataBlockSize() override { return MAX_DATA_BLOCK_SIZE_AES_GCM; }

        int getDataFrameSize() override { return MAX_DATA_FRAME_SIZE_AES_GCM; }

        int getMacSize() override { return AES_GCM_MAC_SIZE; }

        void setIV(void *nonce) override
        {
            memcpy(iv, nonce, AES_GCM_IV_SIZE);
        }

        // read 32byte key file and create session key
        int readKey(std::string keyFile) override
        {
            int ret = AESLocal::readAESKey(keyFile, key);

            // create session key
            AESLocal::deriveKey(key, AES_GCM_KEY_SIZE, iv, AES_GCM_IV_SIZE, sessionKey, AES_GCM_KEY_SIZE);

            return ret;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, AES_GCM_KEY_SIZE);

            // create session key
            AESLocal::deriveKey(key, AES_GCM_KEY_SIZE, iv, AES_GCM_IV_SIZE, sessionKey, AES_GCM_KEY_SIZE);
        }

        // inBuffer  - encrypted data (entire frame including mac)
        // outBuffer - buffer receiving the plain data
        // length    - frame length in inBuffer | frame/inBuffer: [data+mac[POLY1305TLS_MAC_SIZE]]
        // returns 1 on success (authenticated), 0 when mac authentication has failed
        bool decrypt(void *inBuffer, void* outBuffer, size_t length) override
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);
            CryptoPP::byte *mac = static_cast<CryptoPP::byte *>(&in[MAX_DATA_FRAME_SIZE_AES_GCM]);

            AESLocal::incrementIV(iv, AES_GCM_IV_SIZE);

            dec.SetKeyWithIV(sessionKey, AES_GCM_KEY_SIZE, iv);
            bool verified = dec.DecryptAndVerify(out, mac, AES_GCM_MAC_SIZE, iv, AES_GCM_IV_SIZE, NULL, 0, in, MAX_DATA_FRAME_SIZE_AES_GCM);

            if(!verified)
            {
                *global_info.stderrStream << tool::current_time_string() << "::aes_gcm_handler.hpp::AES_GCM_Decrypt::decrypt::ERROR::MAC authentication failed." << std::endl;
            }

            return verified;
        }
};

#endif
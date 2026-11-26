#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <crypto++/hkdf.h>
#include <cryptopp/hmac.h>
#include <crypto++/sha.h>

#include "xchange.hpp"
#include "crypto_interface.hpp"

const int MAC_SIZE                          = CryptoPP::SHA256::DIGESTSIZE;
const int TWOFISH_KEY_LENGTH                = CryptoPP::Twofish::MAX_KEYLENGTH;
const int TWOFISH_IV_LENGTH                 = CryptoPP::Twofish::BLOCKSIZE;
const int TWOFISH_MAX_DATA_FRAME_SIZE       = (((MAX_DATA_FRAME_SIZE - MAC_SIZE) / CryptoPP::Twofish::BLOCKSIZE)  * CryptoPP::Twofish::BLOCKSIZE) - 1;
const int TWOFISH_MAX_DATA_BLOCK_LENGTH     = TWOFISH_MAX_DATA_FRAME_SIZE - DATA_FRAME_HEADER_SIZE;
const int TWOFISH_MAX_ENCRYPTED_BLOCK_COUNT = std::ceil((float)TWOFISH_MAX_DATA_BLOCK_LENGTH / (float)CryptoPP::Twofish::BLOCKSIZE);
const int TWOFISH_FINAL_PADDING_SIZE        = MAX_DATA_FRAME_SIZE - MAC_SIZE - (TWOFISH_MAX_ENCRYPTED_BLOCK_COUNT * CryptoPP::Twofish::BLOCKSIZE);

NAMESPACE_BEGIN(TWOLocal)

void incrementIV(CryptoPP::byte *numArr, size_t size)
{
    for(size_t i = 0; i < size; i++)
    {
        numArr[i]++;
        if(numArr[i] != 0) break;
    }
}

void deriveKey(void *ikm, int ikmLength, CryptoPP::byte *salt, int saltLength, CryptoPP::byte *key, int keyLength)
{
    CryptoPP::byte *ikmPointer = static_cast<CryptoPP::byte *>(ikm);
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(key, keyLength, ikmPointer, ikmLength, salt, saltLength, NULL, 0);
}

NAMESPACE_END


class TWOFISH_HMAC_Encrypt : public EncryptionInterface
{
    private:
        CryptoPP::byte iv[TWOFISH_IV_LENGTH];
        CryptoPP::byte key[TWOFISH_KEY_LENGTH];
        CryptoPP::byte macKey[TWOFISH_KEY_LENGTH];
        CryptoPP::byte sessionKey[TWOFISH_KEY_LENGTH];
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac;
        CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption enc;

        void initIV() { rng.GenerateBlock(iv, TWOFISH_IV_LENGTH); }

    public:
        TWOFISH_HMAC_Encrypt() {
            memset(iv, 0, TWOFISH_IV_LENGTH);
            memset(key, 0, TWOFISH_KEY_LENGTH);
            memset(macKey, 0, TWOFISH_KEY_LENGTH);
            memset(sessionKey, 0, TWOFISH_KEY_LENGTH);
            initIV();
        }

        ~TWOFISH_HMAC_Encrypt() {
            memset(key, 0, TWOFISH_KEY_LENGTH);
            memset(macKey, 0, TWOFISH_KEY_LENGTH);
            memset(sessionKey, 0, TWOFISH_KEY_LENGTH);
        }

        std::string getCipherName() override { return std::string("TWOFISH_HMAC"); }

        CryptoPP::byte *getIV() override { return iv; }

        int getKeySize() override {return TWOFISH_KEY_LENGTH; }

        int getIVSize() override { return TWOFISH_KEY_LENGTH; }

        int getDataBlockSize() override { return TWOFISH_MAX_DATA_BLOCK_LENGTH; }

        int getDataFrameSize() override { return TWOFISH_MAX_DATA_FRAME_SIZE; }

        int readKey(std::string keyFile) override
        {
            int ret_val = tool::readBinaryKey(keyFile, key, TWOFISH_KEY_LENGTH);

            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);
            TWOLocal::deriveKey(key, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, sessionKey, TWOFISH_KEY_LENGTH);

            return ret_val;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, TWOFISH_KEY_LENGTH);

            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);
            TWOLocal::deriveKey(key, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, sessionKey, TWOFISH_KEY_LENGTH);
        }

        void setIV(void *buffer) override
        {
            memcpy(iv, buffer, TWOFISH_IV_LENGTH);
        }

        int encrypt(void *inBuffer, void *outBuffer, size_t length) override
        {
            std::string ciphertext;
            CryptoPP::byte mac[MAC_SIZE] = {0};
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            if(length > TWOFISH_MAX_DATA_FRAME_SIZE)
            {
                std::cerr << "twofish_handler.hpp::TWOFISH_HMAC_Encrypt::encrypt::Data length too large. No space to add MAC." << std::endl;
                std::cerr << "twofish_handler.hpp::TWOFISH_HMAC_Encrypt::encrypt::frame length: " << length << std::endl;
                return 0;
            }

            // data padding
            int padding = TWOFISH_MAX_DATA_FRAME_SIZE - length;
            if(padding) rng.GenerateBlock(&in[length], padding);

            // encrypt
            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);
            enc.SetKeyWithIV(sessionKey, TWOFISH_KEY_LENGTH, iv);

            CryptoPP::StringSource(in, length + padding, true,
                new CryptoPP::StreamTransformationFilter(enc,
                    new CryptoPP::StringSink(ciphertext)
                )
            );

            // copy to target buffer
            int data_size = ciphertext.size();
            memcpy(out, ciphertext.data(), ciphertext.size());
            padding = MAX_DATA_FRAME_SIZE - MAC_SIZE - data_size;

            if(padding == TWOFISH_FINAL_PADDING_SIZE) rng.GenerateBlock(&out[data_size], padding);
            else {
                std::cerr << "twofish_handler.hpp::TWOFISH_HMAC_Encrypt::encrypt::Error::Final padding missmatch." << std::endl;
                return 0;
            }
            data_size += padding;

            // create mac
            TWOLocal::deriveKey(sessionKey, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, macKey, TWOFISH_KEY_LENGTH);
            hmac.Restart();
            hmac.SetKey(macKey, TWOFISH_KEY_LENGTH);
            hmac.Update(out, data_size);
            hmac.Final(mac);
            memcpy(&out[data_size], mac, MAC_SIZE);
            data_size += MAC_SIZE;

            return data_size;
        }
};


class TWOFISH_HMAC_Decrypt : public DecryptionInterface
{
    private:
        CryptoPP::byte iv[TWOFISH_IV_LENGTH];
        CryptoPP::byte key[TWOFISH_KEY_LENGTH];
        CryptoPP::byte macKey[TWOFISH_KEY_LENGTH];
        CryptoPP::byte sessionKey[TWOFISH_KEY_LENGTH];
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac;
        CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption dec;

    public:
        TWOFISH_HMAC_Decrypt() {
            memset(iv, 0, TWOFISH_IV_LENGTH);
            memset(key, 0, TWOFISH_KEY_LENGTH);
            memset(macKey, 0, TWOFISH_KEY_LENGTH);
            memset(sessionKey, 0, TWOFISH_KEY_LENGTH);
        }

        ~TWOFISH_HMAC_Decrypt() {
            memset(key, 0, TWOFISH_KEY_LENGTH);
            memset(macKey, 0, TWOFISH_KEY_LENGTH);
            memset(sessionKey, 0, TWOFISH_KEY_LENGTH); 
        }

        std::string getCipherName() override { return std::string("TWOFISH_HMAC"); }

        int getKeySize() override {return TWOFISH_KEY_LENGTH; }

        int getIVSize() override { return TWOFISH_KEY_LENGTH; }

        int getDataBlockSize() override { return TWOFISH_MAX_DATA_BLOCK_LENGTH; }

        int getDataFrameSize() override { return TWOFISH_MAX_DATA_FRAME_SIZE; }

        int getMacSize() override { return MAC_SIZE; }

        void setIV(void *buffer) override
        {
            memcpy(iv, buffer, TWOFISH_IV_LENGTH);
        }

        int readKey(std::string keyFile) override
        {
            int ret_val = tool::readBinaryKey(keyFile, key, TWOFISH_KEY_LENGTH);

            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);
            TWOLocal::deriveKey(key, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, sessionKey, TWOFISH_KEY_LENGTH);

            return ret_val;
        }

        void setKey(void *buff) override
        {
            memcpy(key, buff, TWOFISH_KEY_LENGTH);

            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);
            TWOLocal::deriveKey(key, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, sessionKey, TWOFISH_KEY_LENGTH);
        }

        bool decrypt(void *inBuffer, void *outBuffer, size_t length) override
        {
            int data_size = MAX_DATA_FRAME_SIZE - MAC_SIZE;
            std::string plaindata;
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *mac = static_cast<CryptoPP::byte *>(&in[data_size]);
            CryptoPP::byte computedMac[MAC_SIZE] = {0};

            TWOLocal::incrementIV(iv, TWOFISH_IV_LENGTH);

            // compare mac
            TWOLocal::deriveKey(sessionKey, TWOFISH_KEY_LENGTH, iv, TWOFISH_IV_LENGTH, macKey, TWOFISH_KEY_LENGTH);
            hmac.Restart();
            hmac.SetKey(macKey, TWOFISH_KEY_LENGTH);
            hmac.Update(in, data_size);
            hmac.Final(computedMac);
            
            if(!CryptoPP::VerifyBufsEqual(mac, computedMac, MAC_SIZE)) {
                std::cerr << "twofish_handler.hpp::TWOFISH_HMAC_Encrypt::decrypt::Error::Data authentification failure." << std::endl;
                return false;
            }

            // decrypt
            dec.SetKeyWithIV(sessionKey, TWOFISH_KEY_LENGTH, iv);
            CryptoPP::StringSource(in, TWOFISH_MAX_ENCRYPTED_BLOCK_COUNT * CryptoPP::Twofish::BLOCKSIZE, true,
                new CryptoPP::StreamTransformationFilter(dec,
                    new CryptoPP::StringSink(plaindata)
                )
            );

            memcpy(outBuffer, plaindata.data(), plaindata.size());

            return true;
        }
};

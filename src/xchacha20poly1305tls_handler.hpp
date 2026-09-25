#ifndef XCHACHA20POLY1305TLS_HPP
#define XCHACHA20POLY1305TLS_HPP

#include <string.h>
#include <sys/random.h>
#include <fstream>
#include <filesystem>

#include <crypto++/cryptlib.h>
#include <crypto++/poly1305.h>
#include <crypto++/chacha.h>
#include <crypto++/osrng.h>
#include <crypto++/sha.h>

const int POLY1305TLS_MAC_SIZE = CryptoPP::Poly1305TLS::DIGESTSIZE;
const int XCHACHA20_IV_SIZE = CryptoPP::XChaCha20::IV_LENGTH;
const int XCHACHA20_KEY_SIZE = CryptoPP::XChaCha20::KEYLENGTH;
const int MAX_DATA_BYTE_PER_FRAME_XPOLY = MAX_DATA_BLOCK_SIZE - POLY1305TLS_MAC_SIZE;

/*
 ****************************
 ***** Shared Functions *****
 ****************************
 */

NAMESPACE_BEGIN(XChaLocal)

void incrementIV(uint8_t *numArr, size_t size)
{
    int i = 0;
    uint8_t carry = 1;

    while(i < size)
    {
        numArr[i] += carry;
        if(numArr[i] > 0) break;
        i++;
    }
}

// reads 32 byte into key array from file, requires a 32 byte key file
// returns 0 on success, 1 on failure
int readXChaCha20Key(std::string keyFile, void *buffer)
{
    std::filesystem::path filePath = keyFile;
    std::filesystem::path absolute_path = std::filesystem::absolute(filePath);

    std::ifstream is(absolute_path, std::ifstream::binary);

    is.read(static_cast<char *>(buffer), XCHACHA20_KEY_SIZE);

    int return_val = is.gcount() != XCHACHA20_KEY_SIZE;

    is.close();

    return return_val;
}

void scrambleKeyWithIV(CryptoPP::byte *key, CryptoPP::byte *scrambledKey, CryptoPP::byte* iv)
{
    CryptoPP::SHA256 hash;
    CryptoPP::byte finalHash[XCHACHA20_KEY_SIZE];

    // hash iv to get a new 256-bit representation
    hash.Update(iv, XCHACHA20_IV_SIZE);
    hash.Final(finalHash);

    uint64_t *scrambled_64 = reinterpret_cast<uint64_t *>(scrambledKey);
    uint64_t *hash_64 = reinterpret_cast<uint64_t *>(finalHash);
    uint64_t *key_64 = reinterpret_cast<uint64_t *>(key);

    for(int i = 0; i < 4; i++)
        scrambled_64[i] = key_64[i] ^ hash_64[i];
}

NAMESPACE_END


class XChaCha20Poly1305TLS_Encrypt
{
    private:
        CryptoPP::byte iv[XCHACHA20_IV_SIZE];
        CryptoPP::byte key[XCHACHA20_KEY_SIZE];
        CryptoPP::byte signKey[XCHACHA20_KEY_SIZE];
        CryptoPP::byte sessionKey[XCHACHA20_KEY_SIZE];
        CryptoPP::XChaCha20::Encryption enc;
        CryptoPP::Poly1305TLS signer;

        void initIV()
        {
            CryptoPP::AutoSeededRandomPool rng;
            rng.GenerateBlock(iv, XCHACHA20_IV_SIZE);
        }

    public:
        XChaCha20Poly1305TLS_Encrypt()
        {
            memset(iv, 0, XCHACHA20_IV_SIZE);
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(signKey, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
            initIV();
        }

        ~XChaCha20Poly1305TLS_Encrypt()
        {
            memset(key, 0x00, XCHACHA20_KEY_SIZE);
            memset(signKey, 0x00, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0x00, XCHACHA20_KEY_SIZE);
        }

        CryptoPP::byte *getIV() { return iv; }

        // read 32byte key file and create session key
        int readKey(std::string keyFile)
        {
            int ret = XChaLocal::readXChaCha20Key(keyFile, key);

            // create session key
            XChaLocal::scrambleKeyWithIV(key, sessionKey, iv);

            return ret;
        }

        // inBuffer  - plain data
        // outBuffer - buffer receiving the encrypted data + mac
        // length    - amount of bytes to encrypt
        // return the size of encrypted data + mac
        // return 0 on failure
        int encrypt(void *inBuffer, void* outBuffer, size_t length)
        {
            CryptoPP::byte mac[POLY1305TLS_MAC_SIZE] = {0};
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            if(length > MAX_DATA_FRAME_SIZE - POLY1305TLS_MAC_SIZE)     // make sure there is space left for the poly1305 MAC
            {
                std::cerr << "xchacha20poly1305tls_handler.hpp::XChaCha20Poly1305TLS_Encrypt::encrypt::Data length too large. No space to add MAC." << std::endl;
                std::cerr << "xchacha20poly1305tls_handler.hpp::XChaCha20Poly1305TLS_Encrypt::encrypt::frame length: " << length << std::endl;
                return 0;
            }

            XChaLocal::incrementIV(iv, XCHACHA20_IV_SIZE);

            // encrypt data
            enc.SetKeyWithIV(sessionKey, XCHACHA20_KEY_SIZE, iv, XCHACHA20_IV_SIZE);
            enc.ProcessData(out, in, length);

            // create mac from encrypted data
            // scramble session key with current iv to create new signing key for mac
            // XChaLocal::scrambleKeyWithIV(sessionKey->data(), signKey->data(), iv);
            XChaLocal::scrambleKeyWithIV(sessionKey, signKey, iv);
            signer.SetKey(signKey, XCHACHA20_KEY_SIZE);
            signer.Update(out, length);
            signer.Final(mac);

            // append MAC to out buffer
            memcpy(&out[length], mac, POLY1305TLS_MAC_SIZE);

            return length + POLY1305TLS_MAC_SIZE;
        }
};

class XChaCha20Poly1305TLS_Decrypt
{
    private:
        CryptoPP::byte iv[XCHACHA20_IV_SIZE];
        CryptoPP::byte key[XCHACHA20_KEY_SIZE];
        CryptoPP::byte signKey[XCHACHA20_KEY_SIZE];
        CryptoPP::byte sessionKey[XCHACHA20_KEY_SIZE];
        CryptoPP::XChaCha20::Decryption dec;
        CryptoPP::Poly1305TLS verifier;

        // buffer:  pointer to encrypted data
        // mac:     pointer to MAC for this encrypted data
        // length:  byte count of enc data in buffer
        // returns 1 if mac confirms buffer integrity; 0 otherwise
        int verifyData(CryptoPP::byte* buffer, CryptoPP::byte* mac, int length)
        {
            XChaLocal::scrambleKeyWithIV(sessionKey, signKey, iv);

            verifier.SetKey(signKey, XCHACHA20_KEY_SIZE);
            verifier.Update(buffer, length);

            bool ret_value = verifier.Verify(mac);

            return ret_value;
        }

    public:
        XChaCha20Poly1305TLS_Decrypt()
        {
            memset(iv, 0, XCHACHA20_IV_SIZE);
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(signKey, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
        }

        ~XChaCha20Poly1305TLS_Decrypt()
        {
            memset(key, 0, XCHACHA20_KEY_SIZE);
            memset(signKey, 0, XCHACHA20_KEY_SIZE);
            memset(sessionKey, 0, XCHACHA20_KEY_SIZE);
        }

        void setIV(void *nonce)
        {
            memcpy(iv, nonce, XCHACHA20_IV_SIZE);
        }

        // read 32byte key file and create session key
        int readKey(std::string keyFile)
        {
            int ret = XChaLocal::readXChaCha20Key(keyFile, key);

            // create session key
            XChaLocal::scrambleKeyWithIV(key, sessionKey, iv);

            return ret;
        }

        // inBuffer  - encrypted data (entire frame including mac)
        // outBuffer - buffer receiving the plain data
        // length    - frame length in inBuffer | frame/inBuffer: [data+mac[POLY1305TLS_MAC_SIZE]]
        // returns 0 on success, 1 on error, error may indicate failing mac authentication
        int decrypt(void *inBuffer, void* outBuffer, size_t length)
        {

            int dataLength = length - POLY1305TLS_MAC_SIZE;

            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);
            CryptoPP::byte *mac = static_cast<CryptoPP::byte *>(&in[dataLength]);

            int verified = verifyData(in, mac, dataLength);
            if(!verified)
            {
                *global_info.stderrStream << "xchacha20poly1305tls_handler.hpp::XChaCha20Poly1305TLS_Decrypt::decrypt::Data/MAC verification failed." << std::endl;
                return 1;
            }

            dec.SetKeyWithIV(sessionKey, XCHACHA20_KEY_SIZE, iv, XCHACHA20_IV_SIZE);
            dec.ProcessData(out, in, dataLength);

            return 0;
        }

        // in buffer to read from, out buffer to write to
        void decryptDataFrameHeader(void *inBuffer, void* outBuffer, size_t length)
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            XChaLocal::incrementIV(iv, XCHACHA20_IV_SIZE);

            dec.SetKeyWithIV(sessionKey, XCHACHA20_KEY_SIZE, iv);
            dec.ProcessData(out, in, length);
        }
};

#endif

#ifndef CHACHA20_HANDLER_HPP
#define CHACHA20_HANDLER_HPP

#include "crypto++/cryptlib.h"
#include "crypto++/chacha.h"
#include "crypto++/sha.h"

#include <sys/random.h>
#include <filesystem>


const int CHACHA20_IV_LENGTH = 8;
const int CHACHA20_KEY_LENGTH = 32;

void increaseIV(CryptoPP::byte *ivArr);
int readChaCha20Key(std::string keyFile, void *buffer);
void scrambleKeyWithIV(CryptoPP::byte *key, CryptoPP::byte *scrambledKey, CryptoPP::byte* iv);


class ChaCha20_Decrypt
{
    private:
        CryptoPP::byte iv[CHACHA20_IV_LENGTH];
        CryptoPP::byte key[CHACHA20_KEY_LENGTH];
        CryptoPP::byte sessionKey[CHACHA20_KEY_LENGTH];
        CryptoPP::ChaCha::Decryption dec;

    public:
        ChaCha20_Decrypt() {}

        void setIV(void *nonce)
        {
            memcpy(iv, nonce, CHACHA20_IV_LENGTH);
        }

        // read 32byte from key file
        int readKey(std::string keyFile)
        {
            int ret = readChaCha20Key(keyFile, key);

            // create session key
            if(!ret) scrambleKeyWithIV(key, sessionKey, iv);

            return ret;
        }

        // expects a 32byte buffer filled with the new key
        void setKey(void *buff)
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            scrambleKeyWithIV(key, sessionKey, iv);
        }

        // in buffer to read from, out buffer to write to
        void decrypt(void *inBuffer, void* outBuffer, size_t length)
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            dec.SetKeyWithIV(sessionKey, CHACHA20_KEY_LENGTH, iv);
            dec.ProcessData(out, in, length);
            increaseIV(iv);
        }

        // in buffer to read from, out buffer to write to
        // decrypt without increasing IV so same stream cipher can be reused to finally decrypt the entire frame
        void decryptDataFrameHeader(void *inBuffer, void* outBuffer, size_t length)
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            dec.SetKeyWithIV(sessionKey, CHACHA20_KEY_LENGTH, iv);
            dec.ProcessData(out, in, length);
        }
};

class ChaCha20_Encrypt
{
    private:
        CryptoPP::byte iv[CHACHA20_IV_LENGTH];
        CryptoPP::byte key[CHACHA20_KEY_LENGTH];
        CryptoPP::byte sessionKey[CHACHA20_KEY_LENGTH];
        CryptoPP::ChaCha::Encryption enc;

        int initIV()
        {
            // read random bytes from /dev/urandom
            ssize_t ret_value = getrandom(iv, CHACHA20_IV_LENGTH, 0);
            return ret_value;
        }

    public:
        ChaCha20_Encrypt()
        {
            initIV();
        }

        CryptoPP::byte *getIV() { return iv; }

        int readKey(std::string keyFile)
        {
            int ret = readChaCha20Key(keyFile, key);

            // create session key
            scrambleKeyWithIV(key, sessionKey, iv);

            return ret;
        }

        // expects a 32byte buffer filled with the new key
        void setKey(void *buff)
        {
            memcpy(key, buff, CHACHA20_KEY_LENGTH);

            // create session key
            scrambleKeyWithIV(key, sessionKey, iv);
        }

        void encrypt(void *inBuffer, void* outBuffer, size_t length)
        {
            CryptoPP::byte *in = static_cast<CryptoPP::byte *>(inBuffer);
            CryptoPP::byte *out = static_cast<CryptoPP::byte *>(outBuffer);

            enc.SetKeyWithIV(sessionKey, CHACHA20_KEY_LENGTH, iv, CHACHA20_IV_LENGTH);
            enc.ProcessData(out, in, length);
            increaseIV(iv);
        }
};



/*
 ********************
 * Shared Functions *
 ********************
*/

void scrambleKeyWithIV(CryptoPP::byte *key, CryptoPP::byte *scrambledKey, CryptoPP::byte* iv)
{
    CryptoPP::SHA256 hash;
    CryptoPP::byte finalHash[CHACHA20_KEY_LENGTH];

    // hash iv
    hash.Update(iv, CHACHA20_IV_LENGTH);
    hash.Final(finalHash);

    // scramble key with iv hash
    uint64_t *scrambled_64 = reinterpret_cast<uint64_t *>(scrambledKey);
    uint64_t *hash_64 = reinterpret_cast<uint64_t *>(finalHash);
    uint64_t *key_64 = reinterpret_cast<uint64_t *>(key);

    for(int i = 0; i < 4; i++)
        scrambled_64[i] = key_64[i] ^ hash_64[i];
}

void increaseIV(CryptoPP::byte *ivArr)
{
    uint64_t *ivPointer = reinterpret_cast<uint64_t *>(ivArr);
    (*ivPointer)++;
}

// reads 32 byte into key array from file, requires a 32 byte key file
// returns 0 on success, 1 on failure
int readChaCha20Key(std::string keyFile, void *buffer)
{
    std::filesystem::path filePath = keyFile;
    std::filesystem::path absolute_path = std::filesystem::absolute(filePath);

    std::ifstream is(absolute_path, std::ifstream::binary);

    is.read(static_cast<char *>(buffer), CHACHA20_KEY_LENGTH);

    int return_val = is.gcount() != CHACHA20_KEY_LENGTH;

    is.close();

    return return_val;
}

#endif
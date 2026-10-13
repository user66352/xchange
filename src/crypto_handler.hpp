#ifndef CRYPTO_HANDLER_HPP
#define CRYPTO_HANDLER_HPP

/*
Encryption and Decryption function as generic classes for all implemented encryption methods (chacha, xchacha, aes, ...)
*/

#include <memory>

#include "aes_gcm_handler.hpp"
#include "chacha20_handler.hpp"
#include "xchacha20poly1305tls_handler.hpp"

class Encryption
{
    private:
        std::unique_ptr<EncryptionInterface> enc_ptr = nullptr;

        void selectEncryptionClass(SECURITY_VERSION type) {
            switch (type)
            {
            case SV_CHACHA20:
                enc_ptr = std::make_unique<ChaCha20_Encrypt>();
                break;

            case SV_XCHACHA20POLY:
                enc_ptr = std::make_unique<XChaCha20Poly1305_Encrypt>();
                break;
            
            case SV_AES_GCM:
                enc_ptr = std::make_unique<AES_GCM_Encrypt>();
                break;
            
            default:
                break;
            }
        }

    public:
        Encryption(SECURITY_VERSION sv) {
            selectEncryptionClass(sv);
        }

        std::string getCipherName() {
            return enc_ptr->getCipherName();
        }

        CryptoPP::byte *getIV() {
            return enc_ptr->getIV();
        }

        int getIVSize() {
            return enc_ptr->getIVSize();
        }

        int getKeySize() {
            return enc_ptr->getKeySize();
        }

        int getDataBlockSize() {
            return enc_ptr->getDataBlockSize();
        }

        int getDataFrameSize() {
            return enc_ptr->getDataFrameSize();
        }

        int readKey(std::string keyFile) {
            return enc_ptr->readKey(keyFile);
        }

        void setKey(void *buff) {
            enc_ptr->setKey(buff);
        }

        int encrypt(void *inBuffer, void* outBuffer, size_t length) {
            return enc_ptr->encrypt(inBuffer, outBuffer, length);
        }
};


class Decryption
{
    private:
        std::unique_ptr<DecryptionInterface> dec_ptr = nullptr;

        void selectDecryptionClass(SECURITY_VERSION sv) {
            switch (sv)
            {
            case SV_CHACHA20:

                #ifdef DEBUG
                std::cout << "crypto_handler.hpp::selectDecryptionClass::select chacha!" << std::endl;
                #endif

                dec_ptr = std::make_unique<ChaCha20_Decrypt>();
                break;

            case SV_XCHACHA20POLY:
            
                #ifdef DEBUG
                std::cout << "crypto_handler.hpp::selectDecryptionClass::select xchacha!" << std::endl;
                #endif

                dec_ptr = std::make_unique<XChaCha20Poly1305_Decrypt>();
                break;

            case SV_AES_GCM:

                #ifdef DEBUG
                std::cout << "crypto_handler.hpp::selectDecryptionClass::select aes!" << std::endl;
                #endif

                dec_ptr = std::make_unique<AES_GCM_Decrypt>();
                break;
            
            default:
                break;
            }
        }

    public:
        Decryption(SECURITY_VERSION sv) {
            selectDecryptionClass(sv);
        }

        std::string getCipherName() {
            return dec_ptr->getCipherName();
        }

        int getIVSize() {
            return dec_ptr->getIVSize();
        }

        int getKeySize() {
            return dec_ptr->getKeySize();
        }

        int getDataBlockSize() {
            return dec_ptr->getDataBlockSize();
        }

        int getDataFrameSize() {
            return dec_ptr->getDataFrameSize();
        }

        int getMacSize() {
            return dec_ptr->getMacSize();
        }

        void setIV(void *nonce) {
            dec_ptr->setIV(nonce);
        }

        int readKey(std::string keyFile) {
            return dec_ptr->readKey(keyFile);
        }

        void setKey(void *buff) {
            dec_ptr->setKey(buff);
        }

        // in buffer to read from, out buffer to write/decrypt to
        // length: total frame size including mac
        // return true if verified, false if mac authentication has failed
        bool decrypt(void *inBuffer, void* outBuffer, size_t length) {
            return dec_ptr->decrypt(inBuffer, outBuffer, length);
        }
};

#endif
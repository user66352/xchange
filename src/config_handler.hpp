#ifndef CONFIG_HANDLER_HPP
#define CONFIG_HANDLER_HPP

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <crypto++/base64.h>

#include "xchange.hpp"

// #define CLIENT
// #define SERVER

#ifdef CLIENT
const std::string BASE_CONFIG_DIR{".config/xchange/client/"};
const std::string LOCAL_ID_FILE{"client.id"};
const std::string REMOTE_ID_FILE{"server.id"};

struct LOCAL_CONFIG_BASE64 {
    std::string uid_hex = "";
    std::string public_key_b64 = "";
    std::string private_key_b64 = "";
};

struct REMOTE_CONFIG_BASE64 {
    std::string publik_key_b64 = "";
    std::string alias = "";
    std::string ip = "";
};
#endif

#ifdef SERVER
const std::string BASE_CONFIG_DIR{".config/xchange/server/"};
const std::string LOCAL_ID_FILE{"server.id"};
const std::string REMOTE_ID_FILE{"client.id"};

struct LOCAL_CONFIG_BASE64 {
    std::string public_key_b64 = "";
    std::string private_key_b64 = "";
};

struct REMOTE_CONFIG_BASE64 {
    std::string publik_key_b64 = "";
    std::string uid_hex = "";
};
#endif


class CONFIG_MANAGER
{
    public:
        CONFIG_MANAGER() = default;
        virtual ~CONFIG_MANAGER() = default;
        virtual int isError() = 0;
        virtual std::string GetClientUID() = 0;
        virtual int ReadLocalKeys(void *publicKey, void *privateKey) = 0;
        virtual int ReadRemotePublicKey(std::string id, void *publicKey) = 0;
};


#ifdef SERVER
class Config_Manager_Server : public CONFIG_MANAGER
{
    private:
        std::vector<REMOTE_CONFIG_BASE64> remoteVec;
        std::filesystem::path config_dir{""};
        std::filesystem::path local_id_file{""};
        std::filesystem::path remote_id_file{""};
        LOCAL_CONFIG_BASE64 local_config_b64;
        int error = 0;

        std::string GetClientUID() override { return ""; }

        bool DirectoryExist(std::filesystem::path dir)
        {
            return std::filesystem::status(dir).type() == std::filesystem::file_type::directory;
        }

        bool FileExists(std::filesystem::path filepath)
        {
            return std::filesystem::status(filepath).type() == std::filesystem::file_type::regular;
        }

        // store local config in local_config_b64
        // return 0 on success, 1 on failure
        int ParseLocalIdFile()
        {
            std::string line{""};
            std::vector<std::string> tokens;
            std::ifstream id_file(local_id_file);

            if(id_file.is_open())
            {
                while(std::getline(id_file, line)) {
                    tokens = tool::splitString(line, ' ');
                    if(tokens.at(0).front() == '#' || tokens.size() != 2) continue;
                    local_config_b64.public_key_b64  = tokens[0];
                    local_config_b64.private_key_b64 = tokens[1];
                }
            } else return 1;

            id_file.close();

            return 0;
        }

        int ParseRemoteIdFile()
        {
            std::string line{""};
            std::vector<std::string> tokens;
            std::ifstream id_file(remote_id_file);

            if(id_file.is_open()) {
                while(std::getline(id_file, line)) {
                    tokens = tool::splitString(line, ' ');
                    if(tokens.at(0).front() == '#' || tokens.size() != 2) continue;
                    remoteVec.emplace_back(REMOTE_CONFIG_BASE64{});
                    remoteVec.back().uid_hex        = tokens[0];
                    remoteVec.back().publik_key_b64 = tokens[1];
                }
            } else return 1;

            return 0;
        }

        void BinaryToBase64(void *data, size_t size, std::string &encoded)
        {
            CryptoPP::StringSource(static_cast<CryptoPP::byte *>(data), size, true,
                new CryptoPP::Base64Encoder(
                    new CryptoPP::StringSink(encoded),
                    false
                )
            );
        }

        // decods a base64 string and stores the decoded bytes starting at binary_pointer
        // returns 0 on success, 1 on failure
        int Base64KeyToBinary(std::string &base64, void *binary_pointer, size_t key_size)
        {
            std::string decoded;

            CryptoPP::StringSource(base64, true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::StringSink(decoded)
                )
            );

            if(decoded.size() != key_size) return 1;

            memcpy(binary_pointer, decoded.data(), decoded.size());

            return 0;
        }

        // stores the binary public key in data
        // size is the expected length of the binary key in byte
        // returns 0 on success, 1 on failure
        int GetLocalPublicKey(void *data, size_t size) {
            return Base64KeyToBinary(local_config_b64.public_key_b64, data, size);
        }

        // stores the binary private key in data
        // size is the expected length of the binary key in byte
        // returns 0 on success, 1 on failure
        int GetLocalPrivateKey(void *data, size_t size) {
            return Base64KeyToBinary(local_config_b64.private_key_b64, data, size);
        }

        // return the amount of bytes converted into bytes or -1 on failure
        // uid bytes stored at data pointer
        // buffSize is the expected length of the uid binary/buffer size of data pointer
        int GetUIDBinary(std::string uid_hex, void *data, size_t buffSize) {
            if(uid_hex.size() % 2 > 0) return -1;
            if(uid_hex.size() / 2 > buffSize) return -1;
            return tool::hexToByte(uid_hex, data);
        }

        // returns 0 if valid config found else 1
        int init()
        {
            char *homeDir = getenv("HOME");
            if(!homeDir) return 1;

            std::string homeDirStr = homeDir;
            homeDirStr.append("/");
            config_dir = std::filesystem::path(homeDirStr + BASE_CONFIG_DIR);

            local_id_file = std::filesystem::path{config_dir.string() + LOCAL_ID_FILE };
            remote_id_file = std::filesystem::path{config_dir.string() + REMOTE_ID_FILE };

            if(!FileExists(local_id_file)) return 1;
            if(!FileExists(remote_id_file)) return 1;

            if(ParseLocalIdFile()) return 1;
            if(ParseRemoteIdFile()) return 1;

            return 0;
        }

    public:
        Config_Manager_Server() { error = init(); }

        ~Config_Manager_Server() {
            memset(local_config_b64.private_key_b64.data(), 0x00, local_config_b64.private_key_b64.size());
            memset(&local_config_b64, 0x00, sizeof(LOCAL_CONFIG_BASE64));
        }

        int isError() override { return error; }

        int ReadLocalKeys(void *publicKey, void *privateKey) override
        {
            int err = 0;
            err  = Base64KeyToBinary(local_config_b64.public_key_b64, publicKey, MAX_KEY_SIZE);
            err |= Base64KeyToBinary(local_config_b64.private_key_b64, privateKey, MAX_KEY_SIZE);
            return err;
        }

        int ReadRemotePublicKey(std::string id, void *publicKey) override
        {
            int err = 1;
            for(auto &ri : remoteVec) {
                if(ri.uid_hex == id) {
                    err = Base64KeyToBinary(ri.publik_key_b64, publicKey, MAX_KEY_SIZE);
                    break;
                }
            }
            return err;
        }

        bool isUIDValid(void* uid) {
            bool valid = false;
            std::string uidstr = tool::byteToHex(uid, CLIENT_ID_SIZE, 'u');
            for(auto id : remoteVec) {
                valid = id.uid_hex == uidstr;
                if(valid) break;
            }
            return valid;
        }
};
#endif

#ifdef CLIENT
class Config_Manager_Client : public CONFIG_MANAGER
{
    private:
        std::vector<REMOTE_CONFIG_BASE64> remoteVec;
        std::filesystem::path config_dir{""};
        std::filesystem::path local_id_file{""};
        std::filesystem::path remote_id_file{""};
        LOCAL_CONFIG_BASE64 local_config_b64;
        int error = 0;

        bool DirectoryExist(std::filesystem::path dir)
        {
            return std::filesystem::status(dir).type() == std::filesystem::file_type::directory;
        }

        bool FileExists(std::filesystem::path filepath)
        {
            return std::filesystem::status(filepath).type() == std::filesystem::file_type::regular;
        }

        // store local config in local_config_b64
        // return 0 on success, 1 on failure
        int ParseLocalIdFile()
        {
            std::string line{""};
            std::vector<std::string> tokens;
            std::ifstream id_file(local_id_file);

            if(id_file.is_open())
            {
                while(std::getline(id_file, line)) {
                    tokens = tool::splitString(line, ' ');
                    if(tokens.at(0).front() == '#' || tokens.size() != 3) continue;
                    local_config_b64.uid_hex         = tokens[0];
                    local_config_b64.public_key_b64  = tokens[1];
                    local_config_b64.private_key_b64 = tokens[2];
                }
            } else return 1;

            id_file.close();

            return 0;
        }

        int ParseRemoteIdFile()
        {
            std::string line{""};
            std::vector<std::string> tokens;
            std::ifstream id_file(remote_id_file);

            if(id_file.is_open()) {
                while(std::getline(id_file, line)) {
                    tokens = tool::splitString(line, ' ');
                    if(tokens.at(0).front() == '#' || tokens.size() != 3) continue;
                    remoteVec.emplace_back(REMOTE_CONFIG_BASE64{});
                    remoteVec.back().alias          = tokens[0];
                    remoteVec.back().ip             = tokens[1];
                    remoteVec.back().publik_key_b64 = tokens[2];
                }
            } else return 1;

            return 0;
        }

        void BinaryToBase64(void *data, size_t size, std::string &encoded)
        {
            CryptoPP::StringSource(static_cast<CryptoPP::byte *>(data), size, true,
                new CryptoPP::Base64Encoder(
                    new CryptoPP::StringSink(encoded),
                    false
                )
            );
        }

        // decods a base64 string and stores the decoded bytes starting at binary_pointer
        // returns 0 on success, 1 on failure
        int Base64KeyToBinary(std::string &base64, void *binary_pointer, size_t key_size)
        {
            std::string decoded;

            CryptoPP::StringSource(base64, true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::StringSink(decoded)
                )
            );

            if(decoded.size() != key_size) return 1;

            memcpy(binary_pointer, decoded.data(), decoded.size());

            return 0;
        }

        // stores the binary public key in data
        // size is the expected length of the binary key in byte
        // returns 0 on success, 1 on failure
        int GetLocalPublicKey(void *data, size_t size) {
            return Base64KeyToBinary(local_config_b64.public_key_b64, data, size);
        }

        // stores the binary private key in data
        // size is the expected length of the binary key in byte
        // returns 0 on success, 1 on failure
        int GetLocalPrivateKey(void *data, size_t size) {
            return Base64KeyToBinary(local_config_b64.private_key_b64, data, size);
        }

        // return the amount of bytes converted into bytes or -1 on failure
        // uid bytes stored at data pointer
        // buffSize is the expected length of the uid binary/buffer size of data pointer
        int GetUIDBinary(void *data, size_t buffSize) {
            if(local_config_b64.uid_hex.size() % 2 > 0) return -1;
            if(local_config_b64.uid_hex.size() / 2 > buffSize) return -1;
            return tool::hexToByte(local_config_b64.uid_hex, data);
        }

        // returns 0 if valid config found else 1
        int init()
        {
            char *homeDir = getenv("HOME");
            if(!homeDir) return 1;

            std::string homeDirStr = homeDir;
            homeDirStr.append("/");
            config_dir = std::filesystem::path(homeDirStr + BASE_CONFIG_DIR);

            local_id_file = std::filesystem::path{config_dir.string() + LOCAL_ID_FILE };
            remote_id_file = std::filesystem::path{config_dir.string() + REMOTE_ID_FILE };

            if(!FileExists(local_id_file)) return 1;
            if(!FileExists(remote_id_file)) return 1;

            if(ParseLocalIdFile()) return 1;
            if(ParseRemoteIdFile()) return 1;

            return 0;
        }

    public:
        Config_Manager_Client() { error = init(); }

        ~Config_Manager_Client() {
            memset(local_config_b64.private_key_b64.data(), 0x00, local_config_b64.private_key_b64.size());
            memset(&local_config_b64, 0x00, sizeof(LOCAL_CONFIG_BASE64));
        }

        int isError() override { return error; }

        int ReadLocalKeys(void *publicKey, void *privateKey) override
        {
            int err = 0;
            err  = Base64KeyToBinary(local_config_b64.public_key_b64, publicKey, MAX_KEY_SIZE);
            err |= Base64KeyToBinary(local_config_b64.private_key_b64, privateKey, MAX_KEY_SIZE);
            return err;
        }

        int ReadRemotePublicKey(std::string id, void *publicKey) override
        {
            int err = 1;
            for(auto &ri : remoteVec) {
                if(ri.alias == id) {
                    err = Base64KeyToBinary(ri.publik_key_b64, publicKey, MAX_KEY_SIZE);
                    break;
                }
            }
            return err;
        }

        std::string GetClientUID() override
        {
            return local_config_b64.uid_hex;
        }

        std::string GetServerIP(std::string alias)
        {
            std::string ip{""};
            for(auto &ri : remoteVec) {
                if(ri.alias == alias) {
                    ip = ri.ip;
                    break;
                }
            }
            return ip;
        }
};
#endif

#endif

#ifndef HELP_HPP
#define HELP_HPP

const char *xcc_help_text =
"\
xchange client help:\n\n\
Usage:\n\
client [Options] [Data:text|file]\n\n\
-s <ip>                                         Server IP (IPv4 address, no DNS resolve in this version)\n\n\
-p|--port <server tcp port>                     Target TCP port. Defaults to 9009 if omitted.\n\n\
-m|--message <message string>                   Send a message. Message length depends on the choosen encryption (max 1450 byte).\n\n\
-f|--file <file_path>                           Path of file to send.\n\n\
-n|--name <file name>                           File name that is transmitted if file is piped into xcc.\n\
                                                Under that name the data will be saved as file by xcd.\n\
                                                Only required when used with '--stdin file'.\n\n\
--stdin [message|file]                          If set a message or file will be read from stdin.\n\
                                                When 'file' is selected also --name must be provided.\n\n\
-e|--encryption <encryption mode>               If ommitted data is transfered ChaCha20-Poly1305 encrypted (equal to '-e cha').\n\
                                                Available encryption modes: 'cha' - ChaCha20-Poly1305, 'xch' - XChaCha20-Poly1305, 'aes' - AES-256-GCM, 'two' - Twofish-CBC-HMAC\n\n\
-k|--key <key file>                             A 32 byte long key file used for selected encryption mode.\n\
                                                When this key is set xcc will use it to authenticate the key exchange with the server.\n\
                                                If omitted xcc will default to unauthtenticated key exchange.\n\n\
-S|--stats                                      Print transfer statistics in file mode. Amount of user data transfered in byte.\n\n\
-P|--progress                                   Print progress in file mode. Includes --stats. \n\n\
--print-new-id                                  Print a new client id to stdout\n\
                                                Format: UID PUBLIC-KEY PRIVATE-KEY\n\
                                                It can be redirected to override the local client.id: xcc --print-new-id > /home/user/.config/xchange/client/client.id\n\n\
-b|--bandwidth <bandwidth in byte>              Bytes sent per second in file mode. Used to throttle the transfer throughput.\n\n\
-h|--help                                       Print this help.\n\n\
-v|--version                                    Print version.\n\n\
Xcc takes either a message (-m) or a file (-f).\n\n\
Examples:\n\
xcc -s 192.168.100.200 -m 'do not forget this message'\n\
xcc -s 192.168.100.200 -p 10000 -f /path/to/my/file\n\
xcc -s 192.168.100.200 --port 10000 --key keyfile.bin --encryption aes --stdin file --name data.dat < data.dat\n\
echo 'very important message' | xcc -s 192.168.100.200 --key keyfile.bin --encryption cha --stdin message";


const char *xcd_help_text =
"\
-i <IPv4>               - IP the server will listen on, if omitted will default to any (0.0.0.0)\n\n\
-p <port>               - TCP port for incoming connections, if omitted defaults to 9009\n\n\
-o <out_folder>         - download folder to store incoming files, if omitted the file will be redirected to stdout\n\
                          incompatible with omitting -m\n\n\
-m <msg_file>           - file to store incoming messages, if omitted messages will be printed to stdout\n\
                          incompatible with omitting -o\n\n\
-e <log_file>           - path to file containing log messages, if omitted errors are redirected to stderr\n\n\
-k <key file>           - Key file used for all encryption methods.\n\
                          This key is being used to authenticated the public key exchange between client and server (protocol: apsk).\n\n\
--print-new-id          - Prints a new public/private key pair to stdout to be used in server.id.\n\
                          Can be used to override existing local id:\n\
                          xcd --print-new-id > /home/user/.config/xchange/server/server.id\n\n\
--wl-encryption         - Define a whitelist for allowed encryption methods a client can connect with.\n\
                          The list must be comma-separated (--wl-encryption aes,xch).\n\n\
--wl-protocol           - Define a whitelist for allowed protocol versions.\n\
                          The list must be comma-separated (--wl-protocol apsk,kpk).\n\
                          Available protocols are: uaut,apsk,kpk.\n\
                          uaut: Unathenticated Public Key Exchange (connect without an pre-shared-key)\n\
                          apsk: Authenticated Public Key Exchange (authenticated with PSK)\n\
                          kpk:  Authenticated key exchange based on locally known public keys\n\n\
-h                      - print this help\n\n\
-v                      - print version";


#endif
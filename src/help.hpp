#ifndef HELP_HPP
#define HELP_HPP

const char *xcc_help_text =
"\
xchange client help:\n\n \
Usage:\n \
client [Options] [Data:text|file]\n\n \
-s <ip>                                         Server IP (IPv4 address, no DNS resolve in this version)\n\n \
-p|--port <server tcp port>                     Target TCP port. Defaults to 9009 if omitted.\n\n \
-m|--message <message string>                   Send a message. Message length depends on the choosen encryption (max 1450 byte).\n\n \
-f|--file <file_path>                           Path of file to send.\n\n \
-n|--name <file name>                           File name that is transmitted if file is piped into xcc.\n \
                                                Under that name the data will be saved as file by xcd.\n \
                                                Only required when used with '--stdin file'.\n\n \
--stdin [message|file]                          If set a message or file will be read from stdin.\n \
                                                When 'file' is selected also --name must be provided.\n\n \
-e|--encryption <encryption mode>               If ommitted data is transfered as plain text/unencrypted.\n \
                                                Available encryption modes: 'cha' - ChaCha20-Poly1305, 'xch' - XChaCha20-Poly1305, 'aes' - AES-256-GCM\n\n \
-k|--key <key file>                             Key file used for selected encryption mode.\n\n \
-S|--stats                                      Print transfer statistics in file mode. Amount of user data transfered in byte.\n\n \
-P|--progress                                   Print progress in file mode. Includes --stats. \n\n \
-b|--bandwidth <bandwidth in byte>              Bytes sent per second in file mode. Used to throttle the transfer throughput.\n\n \
-h|--help                                       Print this help.\n\n \
-v|--version                                    Print version.\n\n \
The program takes either a message (-m) or a file (-f).\n\n \
Examples:\n \
xcc -s 192.168.100.200 -m 'do not forget this message'\n \
xcc -s 192.168.100.200 -p 10000 -f /path/to/my/file\n \
xcc -s 192.168.100.200 --port 10000 --key keyfile.bin --encryption aes --stdin file --name data.dat < data.dat\n \
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
-k <key file>           - Key file used for all encryption methods.\n\n\
-h                      - print this help\n\n\
-v                      - print version";


#endif
#ifndef HELP_HPP
#define HELP_HPP

const char *xcc_help_text =
"\
xchange client help:\n\n \
Usage:\n \
client [Options] [Data:text|file]\n\n \
-s <ip> Server IP (IPv4 address, no DNS resolve in this version)\n \
-p <server tcp port> (defaults to 9009 if omitted)\n \
-m 'message string' Send a message.\n \
-f <file_path>  Path of file to send.\n \
-e <encryption mode>    If ommitted datas transfered as plain text/unencrypted. Available encryption modes: cha (ChaCha20); xch (XChaCha20Poly1305)\n \
-k <key file>   Key file used for selected encryption mode.\n \
-S Print transfer statistics.\n \
-b <bandwidth in byte>  Bytes sent per second. By default the client tries to write to the socket as fast as possible. Only applied when sending a file.\n \
-h Print this help.\n \
The program takes either a message (-m) or a file (-f).\n\n \
Examples:\n\n \
client -s 192.168.100.200 -m 'do not forget this message'\n \
client -s 192.168.100.200 -p 10000 -f /path/to/my/file";


const char *xcd_help_text =
"\
-i <IPv4>               - IP the server will listen on, if omitted will default to any (0.0.0.0)\n\n\
-p <port>               - TCP port for incoming connections, if omitted defaults to 9009\n\n\
-o <out_folder>         - download folder to store incoming files, if omitted the file will be redirected to stdout\n\
                          incompatible with omitting -m\n\n\
-m <msg_file>           - file to store incoming messages, if omitted messages will be printed to stdout\n\
                          incompatible with omitting -o\n\n\
-e <log_file>           - path to file containing log messages, if omitted errors are redirected to stderr\n\n\
-kc <ChaCha20 key file> - Key file used to decrypt ChaCha20 streams. If not set ChaCha20 connections will be refused.\n\
-h                      - print this help\n\n\
-v                      - print version";


#endif
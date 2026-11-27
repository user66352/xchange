## About  

Xchange is a command line tool consisting of a client (xcc) and server (xcd).  
It has a very narrow scope: provide a simple way to quickly send files and messages to a remote system while also offer client authentication and strong encryption.  
Xchange is not a file sharing tool.  
  
  
## Features  
  
- a client connects directly to a remote machine, no relay server, no 3rd party infrastructure or cloud provider required  
- no passwords, client authentication based on pre-shared keys (symmetric or public keys)  
	- after initial key setup the client is launched with a single command (+ options) without any further user interaction  
- GNU-like command line syntax for straightforward script integration/automation  
- data can be send via a pipe to the client (cat file.dat | xcc ...)  
- end-to-end encryption with authenticated key exchange (X25519)  
- forward secrecy with ephemeral keys  
- uses only strong 256bit keys  
- within trusted local networks the server can be started without any keys configured  
	- but without pre-shared keys the key exchange is performed unauthenticated  
- supports multiple encryption modes (ChaCha, XChaCha, AES, Twofish)  
	- all modes using message authentication  
- minimum dependencies, the only non-standard library required is libcrypto++ (ver. 8.9.0)  
- written for POSIX compliant OS  
  
Regarding limitations, in its current release state a message can not be longer than 1 data frame.  
That’s currently at least 1413 Byte per message (depending on the selected encryption).  
So longer messages need to be send as file.  
  
The largest possible file size is about 6TB.  
Right now the server closes any transfer after 2³² received frames.   
Up to 10 clients can connect at the same time.  
  
  
## Usage  
  
A client can choose one out of 3 connection methods:  
	- authenticated with shared public keys  
	- authenticated with a shared and secret symmetric key  
	- unauthenticated but encrypted

To prevent unauthenticated clients whitelist both or one of the protocols supporting authentication.  
For example `--wl-protocol kpk` will allow only clients whose public key and uid was previously configured on the server.  
With `--wl-protocol apsk` client and server are using a symmetric key that is the same for all clients.  
Providing the `--key` option on the client will trigger it to use `apsk`, while using `--alias` instead of a server ip will use mode `kpk` (pre-configured known-public-keys).  
Not providing a key or an alias will enforce an unauthenticated key exchange.  
That is only recommended if the server is reachable only from within a trusted local network.  
In any other case specific keys should be used and enforced by whitelisting only an authenticated protocol on the server.  
  
Public keys and local public/private key pairs are stored in /home/user/.config/xchange/[client|server]/.  
See CHANGELOG.md at version 0.2.1 for a more detailed description of local file/key setup.  
  
  
### Server (xcd):  

- forward incoming files to a folder, messages printed to stdout/the terminal  

```bash
xcd -o /path/to/received/files
```  

- when used as a daemon you may want to specify all options  
- dedicated port (default is 9009), listening to a dedicated local ip (defaults to 0.0.0.0), files stored in a folder, messages stored in a specific message file and errors being logged to a log file:  

```bash
xcd -i 192.168.55.10 -p 10111 -k keyfile.bin -o /home/user/receivedFilesDir -m /home/user/receivedMessages.txt -e /home/user/xcdlog.txt
```  

- xcd writing incoming files to `~/receiveDirectory/`
- only allow clients with locally known public keys

```bash
xcd -o ~/receiveDirectory/ --wl-protocol kpk
```
  
- xcd can be stopped by sending SIGINT or CTRL+C on the terminal  
- though thats not a 'graceful' shutdown yet, it will terminate an ongoing transfer 
  
  
### Client (xcc):  

- forward a message with default settings (ChaCha20-Poly1305, unauthenticated key exchange):  

```bash
xcc -s 192.168.55.10 -m "very important message"
```  


- forward a file to a server with a non-default port:  

```bash
xcc -s 192.168.55.10 -p 10111 -f /file/to/forward/file.bin
```  


- send a file with limited bandwidth (in byte per sec) and status information:  

```bash
xcc -s 192.168.55.10 -p 10111 -b 256000 -S -f /file/to/forward/file.bin
```  


- send a message encrypted with ChaCha20Poly1305 and key exchange authenticated by psk loaded from keyfile.key:  

```bash
xcc -s 192.168.55.10 -k keyfile.key -e cha -m 'my message'
```  


- send a file encrypted with ChaCha20Poly1305:  

```bash
xcc -s 192.168.55.10 --key keyfile.key --encryption cha --file /file/to/forward/file.bin
```  

- send a file encrypted with XChaCha20Poly1305:  

```bash
xcc -s 192.168.55.10 -k keyfile.bin -e xch -f /file/to/forward/file.bin
```  


- send a file AES encrypted received via a pipe and print stats after transfer:  

```bash
cat ~/results.csv | xcc -s 192.168.55.10 --stats --key keyfile.bin --encryption aes --stdin file --name results.csv
```  


- send a message received from a pipe:

```bash
echo "highly important message" | xcc -s 192.168.55.10 --key keyfile.bin --encryption xch --stdin message
```  


- send file `data.bin` to a server selected by its alias, using Twofish encryption and printing transfer progress
- `--alias` requires key setup in /home/user/.config/xchange/ for client and server:

```bash
xcc --alias sun --progress --encryption two --file data.bin
```
  
  
## Install  

All thats required is an installed C++ compiler (g++ or clang++) and libcrypto++.  

Install libcrypto++ (Debian 13):  

`sudo apt install libcrypto++-dev libcrypto++8t64`  
  
  
### Compilation  

- clone the repo:  

`git clone https://github.com/user66352/xchange.git`  

- change into the cloned folder:  

`cd xchange`  

- make build.sh executable:  

`chmod +x build.sh`  

- start the build process:  

`./build.sh`  

If the script found a C++ compiler Client (xcc) and Server (xcd) are now located in folder 'bin'.  

Statically linked executables can be generated by adding 'static':  

`./build.sh static`  

Binaries created as 'static' should run on a variety of linux installations.  
I could run them statically build on Debian 13 with kernel 6.12 on an older Debian 11 with kernel 5.10 and no libcrypto++ install.  

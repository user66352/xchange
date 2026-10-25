## What is xchange?  

In short its a client/server application to forward messages and files to a server in a quick and hopefully easy way.  
I found myself repeatedly sitting at my notebook and wanted to forward a quick message to my main system.  
For example to bookmark a link at my main machine.  
Sure I can get up, grab a usb key or open my mail account and send the link to myself.  
Or finding some document, downloading it to my notebook.  
Now how do I forward that to my main system with the least amount of effort?  
I could have pieced together something with netcat or use scp but it just didn’t feel right.  
So I decided to dig a bit into network programming, stumbled across unix sockets and out came xchange.  
  
  
## Features  

Not a lot beyond simple file/message transfer, that was a priority, and with as little additional dependencies as possible.    
You run the client on a remote machine, provide the server address and your message or file as cmd line argument.  
On the server received messages can be forwarded to stdout or a dedicated file for later review.  
For file transfer there is an option to specify a download folder, otherwise files will be just forwarded to stdout.  
But only messages or files, not both at the same time, can be configured for stdout on the server.  
  
Messages and files can be send encrypted with ChaCha20-Poly1305, XChaCha20-Poly1305 or AES-256-GCM (all methods provide E2EE).  
All encrypted data transfers support message authentication.  
Any tampered packed would trigger an authentication failure on the server.  
In that case already received data is being dropped.  
  
Since xchange does not rely on passwords it requires a 32byte key for encryption.  
That key is a pre-shared key file available to the client (xcc) and the server (xcd).  
  
This key should only contain completelly random bytes (not a text file, not typed in by hand).  
For example such a key file can be created with dd:  
  
```dd if=/dev/urandom of=keyfile.bin bs=32 count=1```  
  
If no encryption method was specified xcc will default to plain text transfer.  
To prevent unencrypted traffic and/or unauthorized clients from uploading xcd has the option --whitelist.  
Start xcd with `--whitelist aes,cha,xch` to deny unauthorized clients.  
  
Each transmitted data frame comes with its own checksum and frame counter to guarantee data integrity and in-order frame transfer.  
That`s already done by TCP but better safe than sorry.  
  
Regarding limitations, in its current release state a message can not be longer than 1 data frame.  
That’s currently at least 1434 Byte per message (depending on the selected encryption, 1450 byte without).  
So longer messages need to be send as file.  
  
The largest possible file size is about 6TB.  
Right now the server closes any transfer after 2³² received frames ((0xffffffff - 1) x (~1.4kB per frame)).   
  
It also does not provide any concurrent connections.  
  
Reagarding dependencies, outside of the C/C++ standard library xchange only depends on libcrypto++.  
It should compile and run on all POSIX compliant systems.  
  
Xchange is developed based on libcrypto++ version 8.9.0.  
  
  
## Usage  

### Server (xcd):  

- forward incoming files to a folder, messages printed to stdout/the terminal  

```xcd -o /path/to/received/files```  

- when used as a daemon you may want to specify all options  
- dedicated port (default is 9009), listening to a dedicated local ip (defaults to 0.0.0.0), files stored in a folder, messages stored in a specific message file and errors being logged to a log file:  

```xcd -i 192.168.55.10 -p 10111 -k keyfile.bin -o /home/user/receivedFilesDir -m /home/user/receivedMessages.txt -e /home/user/xcdlog.txt```  

- xcd can be stopped by sending SIGINT or CTRL+C on the terminal  
- though thats not a 'graceful' shutdown yet, it will terminate an ongoing transfer  
  
  
### Client (xcc):  

- forward a message with default settings (no encryption):  

```xcc -s 192.168.55.10 -m "very important message"```  


- forward a file to a server with a non-default port:  

```xcc -s 192.168.55.10 -p 10111 -f /file/to/forward/file.bin```  


- send a file with limited bandwidth (in byte per sec) and status information:  

```xcc -s 192.168.55.10 -p 10111 -b 256000 -S -f /file/to/forward/file.bin```  


- send a message encrypted with ChaCha20Poly1305:  

```xcc -s 192.168.55.10 -k keyfile.key -e cha -m 'my message'```  


- send a file encrypted with ChaCha20Poly1305:  

```xcc -s 192.168.55.10 --key keyfile.key --encryption cha --file /file/to/forward/file.bin```  

- send a file encrypted with XChaCha20Poly1305:  

```xcc -s 192.168.55.10 -k keyfile.bin -e xch -f /file/to/forward/file.bin```  


- send a file AES encrypted received via a pipe and print stats after transfer:  

```cat ~/results.csv | xcc -s 192.168.55.10 --stats --key keyfile.bin --encryption aes --stdin file --name results.csv```  

- send a message received from a pipe:

```echo "highly important message" | xcc -s 192.168.55.10 --key keyfile.bin --encryption xch --stdin message```  


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
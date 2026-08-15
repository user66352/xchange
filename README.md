## What is xchange?  

In short its a client/server application to forward messages and files to a central server in a quick and hopefully easy way.  
I found myself repeatedly sitting at my notebook and wanted to forward a quick message to my main system.  
For example to bookmark a link at my main machine.  
Sure I can get up, grab a usb key or open my mail account and send the link to myself.  
Or finding some document, downloading it to my notebook.  
Now how do I forward that to my main system with the least amount of effort?  
I could have pieced together something with netcat or use scp but it just didn’t feel right.  
So I decided to dig a bit into network programming, stumbled across unix sockets and out came xchange.  


## Features  

Not a lot and that was a priority.  
You run the client on a remote machine, provide the server address and your message or file as cmd line argument and hit enter.  
On the server received messages can be forwarded to stdout or a dedicated file for later review.  
For file transfer there is an option to specify a download folder, otherwise files will be just forwarded to stdout.  
But only messages or files, not both at the same time, can be configured for stdout on the server.  

For now xchange does not support any kind of authentication or encryption.  
All data is transferred as clear text.  
This isn't a big problem for me, since I run it behind a firewall on my local network, which only I have access to.  
So I would not recommend using it outside a network you don’t fully trust, obviously.  

Something I would consider a feature, at least for now, it has no additional dependencies other than libc and the C++ standard library.  
It should, probably, compile and run on all POSIX compliant systems out of the box. (Unix/BSD/Linux/MacOS)  

Each data frame comes with its own chksum and frame counter to guarantee data integrity and in-order frame transfer.  
That`s already done by TCP but better safe than sorry.  

Regarding limitations, in this initial release a message can be not longer than 1 data frame.  
That’s currently 1448 Byte.  
So longer messages need to be send as a file.  

The largest possible file size should be 4TB.  
I say should because I haven’t tested it.  
But the frame counter is a 32bit uint rolling over after 4TB and frame 0 is not expected to contain user data.  


## Usage  

### Server (xcd):  

- forward incoming files to a folder, messages printed to stdout/the terminal  

`xcd -o /path/to/received/files`  


- when used as a daemon you may want to specify all options  
- dedicated port (default is 9009), listening to a dedicated local ip (defaults to 0.0.0.0), files stored in a folder, messages stored in a specific message file and errors being logged to a log file:   

`xcd -i 192.168.55.10 -p 10111 -o /home/peter/receivedFilesDir -m /home/peter/receivedMessages.txt -e /home/peter/xcdlog.txt`  


- start xcd with a ChaCha20 key file to allow ChaCha20 encrypted connection with a shared/symmetric key  

`xcd -kc chacha20.key -o /path/to/received/files`  


### Client (xcc):  

- forward a message with default settings:  

`xcc -s 192.168.55.10 -m "very important message"`  


- forward a file to a server with a non-default port:  

`xcc -s 192.168.55.10 -p 10111 -f /file/to/forward/file.bin`  


- send a file with limited bandwidth (in byte per sec) and status information  

`xcc -s 192.168.55.10 -p 10111 -b 256000 -S -f /file/to/forward/file.bin`  


- send a message encrypted with ChaCha20  

`xcc -s 192.168.55.10 -k chacha20.key -e cha -m 'my message'`  


- send a file encrypted with ChaCha20  

`xcc -s 192.168.55.10 -k chacha20.key -e cha -f /file/to/forward/file.bin`  


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
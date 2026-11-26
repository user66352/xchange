# Change Log  
  
## Ver. 0.2.1  
  
### Added  
  
- as an AES alternative xchange now offers Twofish encryption  
	- Twofish is implemented in CBC mode and uses HMAC for authentication  
	- on the client it is selected with "--encryption two" or whitelisted on the server with "--wl-encryption two"  
  
- xcd is now able to test a clients identity via known public keys  
	- in this mode a client selects a server via its alias  
	- based on that alias the servers ip and public key is read from a local file  
	- the client also now requires its own uid that he transmits to the server to identify itself  
	- based on that identity the server is looking up the clients public key from a local file  
	- this way client and server authenticate each other  
	- when a secure and authenticated channel is created a new key exchange takes place to create ephemeral keys for the actual data exchange  
	- a client can have multiple servers defined in its local server.id, one server definition per line  
	- a server can have multiple clients defined in its local client.id, one client definition per line  
	- local files:  
		- **client:** /home/user/.config/xchange/client/[client.id|server.id]  
                  client.id:  
                  **UID-HEX CLIENT-PUBLIC-KEY-BASE64 CLIENT-PRIVATE-KEY-BASE64**  
                  server.id:  
                  **SERVER-ALIAS SERVER-IP SERVER-PUBLIC-KEY-BASE64**  
		- **server:** /home/user/.config/xchange/server/[client.id|server.id]  
                  server.id:  
                  **SERVER-PUBLIC-KEY-BASE64 SERVER-PRIVATE-KEY-BASE64**  
                  client.id  
                  **CLIENT-UID-HEX CLIENT-PUBLIC-KEY-BASE64**  
	- this new protocol can be white-listed on the server with `--wl-protocol kpk`  
	- it is auto selected on the client when a server is chosen by its alias:  
   		  `xcc --alias server --encryption aes --message "important message"`  
	- a new option on client and server prints a new local id to stdout `--print-new-id`  
	- it can be used to write directly into the local id file to override the existing local id  
		- `xcc --print-new-id > .config/xchange/client/client.id`  
		- `xcd --print-new-id > .config/xchange/server/server.id`  
  
**Examples:**  
  
#### Client  
  
client.id:  
  
```bash  
#UID PUBLIC-KEY PRIVATE-KEY  
1333f40c5f96e668f772fd56 Grp/fE1ZtSRb6QPysCu3JhjjVrpgNr7PulEtsRFkNWw= 8NY3gH7BpEXpqnUWbSpqXNKURoix9ZjZ4mOYyz5+8ns=  
```  
  
server.id:  
  
```bash  
#alias server_ip server_public_key  
sun 192.168.10.10 YSF5eBIbI4uMAD1CZfkD/iANp0VvE4EOFSBXrudf108=  
moon 192.168.10.20 OwSXIHHfRqxecTCwBng/Lr31xB2Af/dWjX5NxI0LkDM=  
```  
  
#### SERVER  
  
server.id:  
  
```bash  
#PUBLIC-KEY PRIVATE-KEY  
OwSXIHHfRqxecTCwBng/Lr31xB2Af/dWjX5NxI0LkDM= OBSSUyedldQmlInEWZ/RG9HEnyD86HK7P5dnxCS2nn8=  
```  
  
client.id:  
  
```bash  
#UID PUBLIC-KEY
1333f40c5f96e668f772fd56 Grp/fE1ZtSRb6QPysCu3JhjjVrpgNr7PulEtsRFkNWw=  
77028f8c4332fcb2c931cb53 C6JGuW7g3ZN8iS4D86kaR+fTlN5NFWFBx2MwM8kI7n0=  
cf5d6365fb094f0bf0fdfd32 wBS9X+csWGv328ruviU54oV8S062drzxPUzGSpAoISI=  
```  
  
  
## Ver. 0.2.0  
  
### Added  
  
- new option '--wl-protocol' (protocol whitelist) for the server (xcd)  
    - to distinguish between different key exchange methods different protocl versions are now being used  
    - by default xcd will allow clients using all protocols  
    - '--wl-protocol' allows to setup a whitelist for key exchange protocls  
    - available protocols:  
    	- 'uaut': unauthenticated public key exchange (no auth key required)  
    	- 'apsk': public key exchange authenticated with a pre-shared-key, that key needs to be available to client and server  
  
### Changed  
  
- encryption keys are now derived via public key exchange (X25519 algorithm)  
    - that exchange can be performed authenticated or unauthenticated  
        - when unauthenticated without psk a Man-in-the-Middle attack would still go undetected  
    - when the client is started providing a key, this key is being used to encrypt and authenticate the initial key exchange  
        - this auth key also needs to be provided to the server  
- by using new keys for every new connection xchange now provides forward secrecy  
- option security whitelist was renamed to --wl-encryption  
  
  
## Ver. 0.1.10  

### Added  

- multithreading for xcd, now up to 10 clients can connect to the server and upload in parallel  
	- more clients would be possible but that would be beyond the expected scope of this project  
	- that can be increased with MAX_CONNECTED_CLIENTS in xchange.hpp  
  
  
## Ver. 0.1.9  

### Fixed  

- a bug that required --whitelist settings, if --whitelist is not set on xcd all encryption modes are now available  
  
  
## Ver. 0.1.8  

### Added
  
- xchange daemon (xcd) got the new option --whitelist  
	- it allows to define allowed encryption methods  
	- with `--whitelist cha,xch,aes` any plain text/unencrypted connections are refused   
	- so only clients with the correct pre-shared key are able to connect and upload  
  
  
## Ver. 0.1.7  

### Added  

- xchange client now accepts data from a pipe (files + messages)
    - read data from a pipe is selected with new option `--stdin [file|message]`  
    - when a file (`--stdin file`) is being received via a piped its name must be provided with option `--name`  

### Changed   

- server now closes a connection after 2³² received data frames ( min. 1434byte per data frame; max byte per transmission > 6TB )  
- client cli options got reworked to reflect feature changes (read from stdin)  
- some bug fixes  
  
  
## Ver. 0.1.6  
  
### Added  
  
- new encryption mode added: AES-GCM  
	- selected with xcc option '-e aes'  
	- uses GCM for message authentication  
	- requires a 32byte key file (256bit key length)  
  
### Changed  
  
- all encryption protocols now use message authentication (ChaCha20 and XChaCha20 using Poly1305, AES using GCM)  
- all data frames now sent with the same length (in text and file mode for all encrypted modes, not in plain mode)  
	- before encrypting a frame its padded with random data (if necessary)  
	- this way message length is not longer revealed by the transmitted frame size  
- using HKDF now to derive the session key  
- general code restructuring to increase maintainability  
- xcd keyfile option changed to '-k' (from -kc)  
  
  
## Ver. 0.1.4  

### Added  

- xchange now supports XChaCha20 with Poly1305 message authentication  
	* it is being selected with '-e xch' on the client  
	* at the moment xcd uses the same key for ChaCha20 and XChaCha20

### Changed  

- small code enhacements to increase stability and performance (slightly)  


## Ver. 0.1.3  

- first version supporting encryption  
- encryption implemented based on libcrypto++  

### Added  

- encryption with stream cipher ChaCha20 with a symmetric key  
	* server must be started with a 32byte key file provided as argument to allow an encrypted connection  
	* the key file is expected to be a file filled with 32 random byte  
	* how to create a key file with dd:  
		* `dd if=/dev/urandom of=chacha20.key bs=32 count=1`  
- bandwidth control in byte per second (client side)  
- new status option in client (-S)  
	* provides transfer status in %  
	* summary of amount of bytes successfully transfered  

### Changed  

- source restructured to make it more modular for feature expansion  


## Ver. 0.1.0  

- initial release  

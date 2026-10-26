# Change Log  
  
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

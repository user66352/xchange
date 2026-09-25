# Change Log  

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

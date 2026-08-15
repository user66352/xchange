# Change Log  

## Ver. 0.1.3  

- first version supporting encryption  
- encryption implemented based on crypto++  

### Added  

- encryption with stream cipher ChaCha20 with a symmetric key  
	* server must be started with a 32byte key file provided as argument to allow an encrypted connection  
- bandwidth control in byte per second (client side)  
- new status option in client (-S)  
	* transfer status in %  
	* summary of amount of bytes successfully transfered  

### Changed  

- source restructured to make it more modular for feature expansion  


## Ver. 0.1.0  

- initial release  

#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <fstream>
#include <iostream>

// NOTE, change arguments as you see fit
int cstore_add(char* password, char* archivename, char* filename)
{
	BYTE final_hash[SHA256_BLOCK_SIZE];
	std::vector<BYTE> plaintext;
	std::vector<BYTE> decrypted_text;
    char byte = 0;
	int num_blocks=0;
	BYTE* IV = (BYTE*) malloc(AES_BLOCK_SIZE);
	BYTE* ciphertext = (BYTE*) malloc(plaintext.size());
	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty
	
	// You may want to have a helper function to check for above 2...
	
	// Create Key
	iterate_sha256(password, final_hash, 10000);

	// Check for existing archive
    
    std::ifstream file_name(filename);

    if(!file_name.is_open())
    {
        std::cerr<<"Could not open the file!"<<filename<<" "<<std::endl;
        return EXIT_FAILURE;
    }

    while(file_name.get(byte))
    {
        plaintext.push_back(byte);
    }
	std::cout<<"Plaintext size -- "<<plaintext.size()<<std::endl;
	std::cout<<std::endl;
	// Get new IV
	sample_urandom(IV, AES_BLOCK_SIZE);

    // Encrypt
	num_blocks = encrypt_cbc(plaintext, IV, ciphertext, final_hash, SHA256_BLOCK_SIZE);
	std::cout<<"Blocks number -- "<<num_blocks<<std::endl;
	std::ofstream archive_name(archivename);
	
    if(!archive_name.is_open())
    {
        std::cerr<<"Could not open the file!"<<archivename<<" "<<std::endl;
        return EXIT_FAILURE;
    }
	archive_name << ciphertext << std::endl;
	
	// Decrypt
	decrypt_cbc(ciphertext, decrypted_text, final_hash, SHA256_BLOCK_SIZE, num_blocks);
	
	std::cout<<"Decrypted size -- "<<decrypted_text.size()<<std::endl;
	//Printing decrypted text
	std::copy(decrypted_text.begin(), decrypted_text.end(), 
            std::ostream_iterator<char>(std::cout, ""));
    file_name.close();
	archive_name.close();
	// If existing archive exists you can use helper function
	// Read old HMAC, recompute HMAC and compare...
	
	// If HMAC ok, do for loop, read each file, get new IV, encrypt, append to archive
	
	// Compute new HMAC of updated archive and store it.
	return 0;
}

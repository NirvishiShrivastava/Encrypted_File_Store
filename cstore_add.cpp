#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <fstream>
#include <iostream>
#include <string>

int cstore_add(char* password, char* archivename, std::vector<std::string> &files)
{
	BYTE final_hash[SHA256_BLOCK_SIZE];
    char byte = 0;
	int blocks=0;
	BYTE IV[AES_BLOCK_SIZE];
	std::fstream archive_name(archivename);

	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty
	
	for (int file_iter = 0; file_iter < files.size(); file_iter++) {
		std::vector<BYTE> plaintext;
		std::string filename = files[file_iter];
		std::ifstream file_name(filename);
		// Create Key
		iterate_sha256(password, final_hash, 10000);

		// Check for existing archive
		

		if(!file_name.is_open())
		{
			std::cerr<<"Could not open the file!"<<filename<<" "<<std::endl;
			return EXIT_FAILURE;
		}

		//read plaintext file contents
		while(file_name.get(byte))
		{
			plaintext.push_back(byte);
		}
		std::cout<<"Plaintext size before padding-- "<<plaintext.size()<<std::endl;

		// Perform padding for plaintext
		if(plaintext.size()%AES_BLOCK_SIZE != 0)
		{
			plaintext = pad_cbc(plaintext);
			
		}
		blocks = plaintext.size() / AES_BLOCK_SIZE;

		BYTE ciphertext[(blocks+1) * AES_BLOCK_SIZE];

		std::cout<<"Plaintext size post padding-- "<<plaintext.size()<<std::endl;
		std::copy(plaintext.begin(), plaintext.end(), std::ostream_iterator<char>(std::cout, ""));

		// Get new IV
		sample_urandom(IV, AES_BLOCK_SIZE);

		// Encrypt
		encrypt_cbc(plaintext, IV, ciphertext, final_hash, SHA256_BLOCK_SIZE, blocks);

		std::cout<<"Blocks number -- "<<blocks<<std::endl;
		
		archive_name.open(archivename, std::ios::app);

		archive_name << filename << "<->";
		archive_name << blocks << "<->";
		archive_name << ciphertext<<"<->"<<std::endl;
		archive_name.close();
		std::cout<<filename<<" added successfully to archive!"<<std::endl;
		file_name.close();

	}

	
	
	// If existing archive exists you can use helper function
	// Read old HMAC, recompute HMAC and compare...
	
	// If HMAC ok, do for loop, read each file, get new IV, encrypt, append to archive
	
	// Compute new HMAC of updated archive and store it.
	return 0;
}





























/*int cstore_add(char* password, char* archivename, char* filename)
{
	BYTE final_hash[SHA256_BLOCK_SIZE];
	std::vector<BYTE> plaintext;
	std::vector<BYTE> decrypted_text;
    char byte = 0;
	int blocks=0;
	BYTE IV[AES_BLOCK_SIZE];
	std::ifstream file_name(filename);
	std::fstream archive_name(archivename);

	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty
		
	// Create Key
	iterate_sha256(password, final_hash, 10000);

	// Check for existing archive
    

    if(!file_name.is_open())
    {
        std::cerr<<"Could not open the file!"<<filename<<" "<<std::endl;
        return EXIT_FAILURE;
    }

	//read plaintext file contents
    while(file_name.get(byte))
    {
        plaintext.push_back(byte);
    }
	std::cout<<"Plaintext size before padding-- "<<plaintext.size()<<std::endl;

	// Perform padding for plaintext
	if(plaintext.size()%AES_BLOCK_SIZE != 0)
    {
        plaintext = pad_cbc(plaintext);
        
    }
	blocks = plaintext.size() / AES_BLOCK_SIZE;

	BYTE ciphertext[(blocks+1) * AES_BLOCK_SIZE];

	std::cout<<"Plaintext size post padding-- "<<plaintext.size()<<std::endl;
	std::copy(plaintext.begin(), plaintext.end(), std::ostream_iterator<char>(std::cout, ""));

	// Get new IV
	sample_urandom(IV, AES_BLOCK_SIZE);

    // Encrypt
	encrypt_cbc(plaintext, IV, ciphertext, final_hash, SHA256_BLOCK_SIZE, blocks);

	std::cout<<"Blocks number -- "<<blocks<<std::endl;
	
    // if(!archive_name.is_open())
    // {
    //     std::cerr<<"Could not open the file!"<<archivename<<" "<<std::endl;
    //     return EXIT_FAILURE;
    // }
	archive_name.open(archivename, std::ios::app);
	archive_name << filename;
	archive_name << blocks;
	archive_name << ciphertext;
	archive_name << "<---->";

	std::cout<<filename<<" added successfully to archive!"<<std::endl;


	// Decrypt
	decrypt_cbc(ciphertext, decrypted_text, final_hash, SHA256_BLOCK_SIZE, blocks);
	
	std::cout<<"Decrypted size -- "<<decrypted_text.size()<<std::endl;

	//Printing decrypted text
	std::copy(decrypted_text.begin(), decrypted_text.end(), std::ostream_iterator<char>(std::cout, ""));
    file_name.close();
	archive_name.close();
	// If existing archive exists you can use helper function
	// Read old HMAC, recompute HMAC and compare...
	
	// If HMAC ok, do for loop, read each file, get new IV, encrypt, append to archive
	
	// Compute new HMAC of updated archive and store it.
	return 0;
}
*/
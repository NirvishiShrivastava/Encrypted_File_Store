#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>

typedef unsigned char BYTE;

int cstore_extract(char* password, char* archivename, std::vector<std::string> &files)
{
	// Do Argument Checking
	
	// Compare HMAC
	// Loop over archive for files to extract and write to CWD

	std::fstream archive_name(archivename);
	std::string filedata;
	std::vector<std::string> filedata_vector;
	std::string delim = "<->";
	size_t pos = 0;
	std::vector<std::string>::iterator it;

	// Check if archive exists
    if(!archive_name.is_open())
    {
        std::cerr<<"The archive does not exist!!"<<archivename<<" "<<std::endl;
        return EXIT_FAILURE;
    }

	// Read archive data to a string line by line and push in filedata_vector
	while(getline(archive_name, filedata))
	{
		while ((pos = filedata.find(delim)) != std::string::npos) 
		{
			filedata_vector.push_back(filedata.substr(0, pos));
			filedata.erase(0, pos + delim.length());
    	}
	}
	
    archive_name.close();

	for (int file_iter = 0; file_iter < files.size(); file_iter++) 
	{
		// Finding position of filename in filedata_vector
		it = std::find(filedata_vector.begin(),filedata_vector.end(),files[file_iter]);
   		int file_pos = std::distance(filedata_vector.begin(), it);

		// Blocks are next to filename
		int blocks = std::stoi(filedata_vector[file_pos+1]);

		BYTE ciphertext[(blocks) * AES_BLOCK_SIZE];
		BYTE hash[SHA256_BLOCK_SIZE];
		std::vector<BYTE> plaintext;
		std::string filename = files[file_iter];
		std::ifstream file_name(filename);
		std::vector<BYTE> decrypted_text;

		std::cout<<"blocks from file vector -- "<<blocks<<std::endl;
		std::cout<<"Cipher from file vector -- "<<filedata_vector[file_pos+2]<<std::endl;


		std::string cp = filedata_vector[file_pos+2];
		memcpy(ciphertext, cp.data(), cp.length());
		
		// Create Key
		iterate_sha256(password, hash, 10000);
		
		// Decrypt
		decrypt_cbc(ciphertext, decrypted_text, hash, SHA256_BLOCK_SIZE, blocks);
		
		std::cout<<"Decrypted size -- "<<decrypted_text.size()<<std::endl;

		//Printing decrypted text
		std::copy(decrypted_text.begin(), decrypted_text.end(), std::ostream_iterator<char>(std::cout, ""));
	}

	return 0;
	
}

#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sstream>
using std::string;
using std::ifstream; 
using std::ostringstream;

typedef unsigned char BYTE;

int cstore_extract(char* password, char* archivename, std::vector<std::string> &files)
{
	// Do Argument Checking
	
	// Compare HMAC
	// Loop over archive for files to extract and write to CWD

	std::fstream archive_name(archivename);
	std::string filedata, filedata_hmac, hmac_delim = "<*&>", delim = "[#]";
	std::vector<std::string> filedata_vector;
	size_t pos = 0, pos1 = 0;
	int blocks;
	std::vector<std::string>::iterator it;
	BYTE hash[SHA256_BLOCK_SIZE];

	// Create Key
	iterate_sha256(password, hash, 10000);

	// Check if archive exists
    if(!archive_name.is_open())
    {
        std::cerr<<"The archive does not exist!!"<<archivename<<" "<<std::endl;
        return EXIT_FAILURE;
    }

	filedata_hmac = std::string((std::istreambuf_iterator<char>(archive_name)), std::istreambuf_iterator<char>());
	
	archive_name.close();

	if((pos = filedata_hmac.find(hmac_delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata_hmac.substr(0, pos));
		filedata_hmac.erase(0, pos + hmac_delim.length());
		std::cout<<"\n=====================TRUNCATE HMAC FROM ARCHIVE=============";

	}

	filedata_vector.clear();

	// Read archive data to a string line by line and push in filedata_vector
	while ((pos1 = filedata_hmac.find(delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata_hmac.substr(0, pos1));
		filedata_hmac.erase(0, pos1 + delim.length());
	}

	std::cout<<"Printing Vector From now"<<std::endl;
	for(int i = 0; i < filedata_vector.size();i++)
	{
		std::cout<<filedata_vector[i]<<std::endl;
	}
	std::cout<<"Printing Vector Ends now"<<std::endl;

	// Extraction loop
	for (int file_iter = 0; file_iter < files.size(); file_iter++) 
	{
		// Finding position of filename in filedata_vector
		it = std::find(filedata_vector.begin(),filedata_vector.end(),files[file_iter]);

   		int file_pos = std::distance(filedata_vector.begin(), it);
		std::cout<<"Printing file pos for tracing block --"<<file_pos<<std::endl;
		
		// Blocks are next to filename
		std::cout<<"Printing block in str----"<<filedata_vector[file_pos+1]<<std::endl;
		
		try 
		{
			blocks = std::stoi(filedata_vector[file_pos+1]);
		}
		catch(std::invalid_argument& e)
		{
			std::cerr<<"Blocks should be an int."<<std::endl;
		}
		

		BYTE ciphertext[(blocks) * AES_BLOCK_SIZE];
		
		std::vector<BYTE> plaintext;
		std::string filename = files[file_iter];
		std::ifstream file_name(filename);
		std::vector<BYTE> decrypted_text;

		std::cout<<"\n Blocks from file vector -- "<<blocks<<std::endl;

		std::string cp = filedata_vector[file_pos+2];
		std::cout<<"\n Respective cp -- "<<cp<<std::endl;
		memcpy(ciphertext, cp.data(), cp.length());
		
		// // Create Key
		// iterate_sha256(password, hash, 10000);
		
		// Decrypt
		decrypt_cbc(ciphertext, decrypted_text, hash, SHA256_BLOCK_SIZE, blocks);
		
		std::cout<<"Decrypted size -- "<<decrypted_text.size()<<std::endl;

		//Printing decrypted text
		std::copy(decrypted_text.begin(), decrypted_text.end(), std::ostream_iterator<char>(std::cout, ""));
	}

	return 0;
	
}

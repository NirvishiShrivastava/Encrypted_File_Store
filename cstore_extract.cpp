#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "cstore_delete.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <iterator>

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
	int blocks, archive_exists;
	std::vector<std::string>::iterator it;
	BYTE hash[SHA256_BLOCK_SIZE];

	// Create Key
	iterate_sha256(password, hash, 10000);
	
	
	// Check if archive exists
	archive_exists = verify_archive_exists(archivename);
	if(archive_exists)
	{
		int hmac_is_same = verify_hmacs(archivename, hash);

		if(!hmac_is_same)
		{
			std::cerr<<"Wrong password / archive has been modified!"<<std::endl;
			return EXIT_FAILURE;
		}
	}


	filedata_hmac = std::string((std::istreambuf_iterator<char>(archive_name)), std::istreambuf_iterator<char>());
	
	archive_name.close();

	if((pos = filedata_hmac.find(hmac_delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata_hmac.substr(0, pos));
		filedata_hmac.erase(0, pos + hmac_delim.length());

	}

	filedata_vector.clear();

	// Read archive data to a string line by line and push in filedata_vector
	while ((pos1 = filedata_hmac.find(delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata_hmac.substr(0, pos1));
		filedata_hmac.erase(0, pos1 + delim.length());
	}

	// Extraction loop
	for (int file_iter = 0; file_iter < files.size(); file_iter++) 
	{
		// Finding position of filename in filedata_vector
		it = std::find(filedata_vector.begin(),filedata_vector.end(),files[file_iter]);

   		int file_pos = std::distance(filedata_vector.begin(), it);
			
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

		std::string cp = filedata_vector[file_pos+2];
		memcpy(ciphertext, cp.data(), cp.length());
		
			
		// Decrypt
		decrypt_cbc(ciphertext, decrypted_text, hash, SHA256_BLOCK_SIZE, blocks);
		
		std::ofstream outfile("output.txt", std::ios::out);
		outfile.write((const char *)&decrypted_text[0], decrypted_text.size());
		outfile.close();
		file_name.close();
		
		// Rename and replace file_name with output
		remove(filename.c_str());
		rename("output.txt",filename.c_str());
		//Printing decrypted text
		std::copy(decrypted_text.begin(), decrypted_text.end(), std::ostream_iterator<char>(std::cout, ""));
	}
	cstore_delete(password, archivename, files);

	return 0;
	
}

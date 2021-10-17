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
	int blocks=0, archive_exists;
	BYTE IV[AES_BLOCK_SIZE];

	// Create Key
	iterate_sha256(password, final_hash, 10000);

	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty
	
	// Check if archive already exists
	
	archive_exists = verify_archive_exists(archivename);
	std::cout<<"archive_exists---------"<<archive_exists<<std::endl;
	if(archive_exists)
	{
		int hmac_is_same = verify_hmacs(archivename, final_hash);
		std::cout<<"HMAC IS SAME??---------"<<hmac_is_same<<std::endl;

		if(!hmac_is_same)
		{
			std::cerr<<"Wrong password / archive has been modified!"<<std::endl;
			return EXIT_FAILURE;
		}
	}


	for (int file_iter = 0; file_iter < files.size(); file_iter++) {
		std::vector<BYTE> plaintext;
		std::string filename = files[file_iter];
		std::ifstream file_name(filename);
		std::cout<<"\n ----> File size: "<< files.size();

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
		
		std::ofstream archive_name;
		archive_name.open(archivename, std::ios::app);

		archive_name << filename << "[#]";
		archive_name << blocks << "[#]";
		archive_name << ciphertext<<"[#]";

		archive_name.close();
		std::cout<<filename<<" added successfully to archive!"<<std::endl;
		file_name.close();

	}

	/** Update HMAC **/
	std::string filedata;

	std::ifstream archive_name;
	archive_name.open(archivename);

	filedata = std::string((std::istreambuf_iterator<char>(archive_name)), std::istreambuf_iterator<char>());

	BYTE* new_hmac = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);

	compute_new_hmac(archivename, new_hmac, final_hash);
	
	// Remove old hash from existing archive
	std::vector<std::string> filedata_vector;
	std::string delim = "<*&>";
	size_t pos = 0;
	std::vector<std::string>::iterator it;
	
	if((pos = filedata.find(delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata.substr(0, pos));
		filedata.erase(0, pos + delim.length());
		std::cout<<"\n\n======================DOES IT PRINT THIS===========222222==";

	}

	std::cout<<"\n\nFiledata vector size====="<<filedata_vector.size()<<std::endl;

	if(filedata_vector.size() == 0)
	{
		std::cout<<"\n\nDid I enter in if?????";

		int arch_len = filedata.length();
		// Push new hmac to begin of file
		std::ofstream temp("temp.txt", std::ios::trunc);
		temp << (char*)new_hmac << "<*&>";
		for(int i =0; i<arch_len; i++)
		{
			temp << filedata[i];
		}
		temp.close();
		archive_name.close();
	
		// Rename and replace archive with temp
		remove(archivename);
		rename("temp.txt",archivename);

	}
	else
	{
		std::cout<<"\n\n======================DOES IT PRINT THIS=========333333333==";
		int arch_len = filedata.length();
		std::cout<<"\n\nMessage size====="<<arch_len<<std::endl;
		// Push new hmac to begin of file
		std::ofstream temp("temp.txt", std::ios::trunc);
		for(int i = 0; i < SHA256_BLOCK_SIZE; i++)
		{
			temp << new_hmac[i];
		}
		// temp << (char*)new_hmac << "<*&>";
		temp << "<*&>";
		for(int i =0; i<arch_len; i++)
		{
			temp << filedata[i];
		}
		temp.close();
		archive_name.close();
	
		// Rename and replace archive with temp
		remove(archivename);
		rename("temp.txt",archivename);

	}
	
	
	
	return 0;
}



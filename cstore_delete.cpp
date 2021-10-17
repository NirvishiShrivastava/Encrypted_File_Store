#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <string>
#include <cstring>

typedef unsigned char BYTE;

// Update Argument as you see fit.
int cstore_delete(char* password, char* archivename, std::vector<std::string> &files)
{
	// Check arguments if you haven't already, see cstore_add 
	
	// Create Key
	// Compute HMAC
	// Recompute HMAC, etc.

    std::string filedata_hmac, delim = "[#]", hmac_delim = "<*&>", hmac;
	size_t pos = 0, pos1 = 0, archive_exists;
    std::vector<std::string> filedata_vector;
	std::vector<std::string> filename_list;
	std::vector<std::string>::iterator it;
	BYTE final_hash[SHA256_BLOCK_SIZE];


	std::cout<<"Delete called"<<std::endl;
	std::fstream archive_name(archivename);

	// Create Key
	iterate_sha256(password, final_hash, 10000);
	
	// Check if archive exists
	archive_exists = verify_archive_exists(archivename);
	if(archive_exists)
	{
		int hmac_is_same = verify_hmacs(archivename, final_hash);
		std::cout<<"HMAC IS SAME?-----"<<hmac_is_same<<std::endl;

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
		std::cout<<"\n=====================TRUNCATE HMAC FROM ARCHIVE=============";

	}

	filedata_vector.clear();

	// Read archive data to a string line by line and push in filedata_vector
	while ((pos1 = filedata_hmac.find(delim)) != std::string::npos) 
	{
		filedata_vector.push_back(filedata_hmac.substr(0, pos1));
		filedata_hmac.erase(0, pos1 + delim.length());
	}


    //All Filenames will be at positions 0,3...
	// for(int i=0; i < filedata_vector.size();)
	// {
	// 	filename_list.push_back(filedata_vector[i]);
	// 	i += 3;
	// }

	// Iterate through archive and see which files to delete
	for (int file_iter = 0; file_iter < files.size(); file_iter++) 
	{
		int deleted = 0;
		for (int vec_iter = 0; vec_iter < filedata_vector.size(); vec_iter++) 
		{
			if(filedata_vector[vec_iter].substr(0, (files[file_iter]).length()) == files[file_iter])
			{
				std::vector<std::string>::iterator it_beg, it_end;
				it_beg = filedata_vector.begin() + vec_iter;
				it_end = filedata_vector.begin() + vec_iter + 3;

				filedata_vector.erase(it_beg, it_end);
				std::cout << "Record Deleted!"<< std::endl;
				deleted = 1;
				vec_iter = 0; // Reset search
			}
		}
		if(deleted == 0)
		{
			std::cerr<<"The file name - "<<files[file_iter]<<" does not exist in archive!!"<<std::endl;
		}
	}

	// If last file present was deleted, delete archive
	if(filedata_vector.size() == 0)
	{
		remove(archivename);
		std::cout<<"The last file from archive was deleted, removing archive"<<std::endl;
	}
	else
	{
		std::ofstream temp("temp.txt", std::ios::trunc);
		std::cout<<"Post delete loop"<<std::endl;

		// Add just the updated message content
		for (int i=0; i<filedata_vector.size(); ++i)
		{
			temp<<filedata_vector[i]<<"[#]";
		}
		
		// archive_name.close();
		temp.close();
		
		// Rename and replace archive with temp
		remove(archivename);
		rename("temp.txt",archivename);

		/** Update HMAC **/
		std::string filedata;

		std::ifstream archive_name;
		archive_name.open(archivename);
		BYTE* new_hmac = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);

		compute_new_hmac(archivename, new_hmac, final_hash);
		
		
		std::cout<<"\n\n======================DOES IT PRINT THIS=========333333333==";
		
		// Push new hmac to begin of file
		std::ofstream temp2("temp2.txt", std::ios::trunc);
		temp2 << (char*)new_hmac << "<*&>";

		// Input vector here
		for (int i=0; i<filedata_vector.size(); ++i)
		{
			temp2<<filedata_vector[i]<<"[#]";
		}
		temp2.close();
		archive_name.close();

		// Rename and replace archive with temp2
		remove(archivename);
		rename("temp2.txt",archivename);

	}	

	return 0;
}

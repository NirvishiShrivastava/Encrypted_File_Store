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

	std::fstream archive_name(archivename);
    std::string filedata;
    std::string delim = "[*#]";
	size_t pos = 0;
    std::vector<std::string> filedata_vector;
	std::vector<std::string> filename_list;

	std::cout<<"Delete called"<<std::endl;
    // Check if archive exists
    if(!archive_name.is_open())
    {
        std::cerr<<"The archive name - "<<archivename<<" does not exist!!"<<std::endl;
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

    //All Filenames will be at positions 0,3...
	for(int i=0; i < filedata_vector.size();)
	{
		filename_list.push_back(filedata_vector[i]);
		i += 3;
	}

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

	std::ofstream temp("temp.txt", std::ios::trunc);

	std::cout<<"Post delete loop"<<std::endl;

    for (int i=0; i<filedata_vector.size(); ++i){
		std::cout<<filedata_vector[i]<<std::endl;
		temp<<filedata_vector[i]<<"[*#]";
	}
    
    archive_name.close();
	temp.close();
	
	// Rename and replace archive with temp
	remove(archivename);
	rename("temp.txt",archivename);


	return 0;
}

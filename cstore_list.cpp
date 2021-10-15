#include "cstore_list.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <string>
#include <cstring>

typedef unsigned char BYTE;

// Change argument as needed
int cstore_list(std::string archivename)
{
    // Open archive
    // You could check to see if it at least has an HMAC?

    std::fstream archive_name(archivename);
    std::string filedata;
    std::string delim = "<->";
	size_t pos = 0;
    std::vector<std::string> filedata_vector;
	std::vector<std::string> filename_list;

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
	
    //All Filenames will be at positions 0,3...
	for(int i=0; i < filedata_vector.size();)
	{
		filename_list.push_back(filedata_vector[i]);
		i += 3;
	}

    std::ofstream list_file("list.txt", std::ios::trunc);

    for (int i=0; i<filename_list.size(); ++i){
		list_file<<filename_list[i]<<std::endl;
	}
    
    list_file.close();
    archive_name.close();


    return 0;
}

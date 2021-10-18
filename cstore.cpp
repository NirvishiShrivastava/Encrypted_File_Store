#include <iostream>
#include <unistd.h>
#include <string>
#include <cstring>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"
#include "cstore_list.h"
#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_delete.h"
#include "cstore_utils.h"

int pwd_check(int argc, char* argv[], char* password)
{
    
    if(strcmp(argv[2], "-p")==0)
    {
        password = argv[3];
        
    }
    else
    {
        std::cout<<"Please enter password to proceed: "<<std::endl;
        std::cin >> password;
    }
    
    return 0;
}

int archive_check(int argc, char* argv[], char* archive)
{
    if(strcmp(argv[2], "-p")==0)
    {
        archive = argv[4];
    }
    else
    {
        archive = argv[2];
    }
    return 0;

}

int main(int argc, char* argv[])
{
    std::string filename;

    // Check correct number of arguments (minimum 3)
    if(argc < 3)
    {
        show_usage(argv[0]);
        return 1;
    }
    // Check the function that the user wants to perform on the archive
    std::string function = argv[1];
    if(function == "list")
    {
        std::string archivename = argv[2];
        return cstore_list(archivename);
    }
    else if(function == "add" || function == "extract" || function == "delete")
    {
        // You will need to Parse Args/Check your arguments.
        // Might not be a bad idea to check here if you can successfully open the files, 
        // Check the correct order, etc.
        std::vector<std::string> files = GetFileNames(argc, argv);
        char password[12];
        char archive[20];

        pwd_check(argc, argv, password);
        archive_check(argc, argv, archive);

        if(function == "add")
        {
            return cstore_add(argv[3], argv[4], files);
        }

        if(function == "extract")
        {
            return cstore_extract(argv[3], argv[4], files);

        }

        if(function == "delete")
        {
            return cstore_delete(argv[3], argv[4], files);
        }
        
    }
    else
    {
        std::cerr << "ERROR: cstore <function> must have <function> in: {list, add, extract, delete}.\n";
        return 1;
    }
    

}

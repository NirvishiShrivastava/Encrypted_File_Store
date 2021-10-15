#include <iostream>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"
#include "cstore_list.h"
#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_delete.h"
#include "cstore_utils.h"


int main(int argc, char* argv[])
{
    std::string filename;

    // Check correct number of arguments (minimum 3)
    if(argc < 3)
    {
        //show_usage(argv[0]);
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
        //std::cout<<&files[0]<<std::endl;

        if(function == "add")
        {
            return cstore_add(argv[3], argv[4], files);
        }

        if(function == "extract")
        {
            return cstore_extract();
        }

        if(function == "delete")
        {
            return cstore_delete();
        }
    }
    else
    {
        std::cerr << "ERROR: cstore <function> must have <function> in: {list, add, extract, delete}.\n";
        return 1;
    }

}

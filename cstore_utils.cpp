#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <iostream>
#include <vector>
#include <fstream>


// Create error.txt, place your error message, and this will exit the program.
// void die(const std::string error) 
// {
// 	std::ofstream new_error_file("error.txt", std::ios::out | std::ios::binary | std::ios::app);
// 	if(!new_error_file.is_open()) {
//         	std::cerr << "Could not write to error.txt" << std::endl; 
// 	}
// 	new_error_file << error << std::endl;
// 	new_error_file.close();
// 	exit(1);
// }

// int read_mac_archive(const std::string archivename, BYTE* file_mac, std::vector<BYTE>& file_content, int mac_len)
// {
//     // I/O: Open old archivename

//     // Authenticate with HMAC if existing archive.

//     // Read data as a block:

//     // Copy over the file as two parts: (1) MAC (2) Content

//     old_archive_file.close();
//     return length;
// }

// int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len)
// {
//     // Pad key with 32 bytes to make it 64 bytes long

//     // Inner padding, 64 Bytes

//     // Outer Padding, 64 Bytes

//     // Concatenate ipad and opad section: (o_key_pad || H(i_key_pad || m))
//     // First, concatenate i_key_pad and message, then hash


//     // Second, concatenate the o_key_pad and H(i_key_pad || m)

//     // Finally, hash the entire thing
// }

// Implement Padding if the message can't be cut into 32 size blocks
std::vector<BYTE> pad_cbc(std::vector<BYTE> data)
{
    int padding_num = AES_BLOCK_SIZE - data.size()%AES_BLOCK_SIZE;
    for (size_t i = 0; i < padding_num; i++)
    {
        data.push_back('\0');
    }
    return data;
}

// Remove the padding from the data after it is decrypted.
std::vector<BYTE> unpad_cbc(std::vector<BYTE> padded_data)
{
    std::vector<BYTE> unpadded_plaintext;
    int i = 0;
    while(padded_data[i] != '\0') 
    {
        unpadded_plaintext.push_back(padded_data[i]);
        i++;

    }
    std::cout<<"Unpadded plaintext size -- "<<unpadded_plaintext.size()<<std::endl;
    return unpadded_plaintext;
}

int encrypt_cbc(std::vector<BYTE> plaintext, const BYTE * IV, BYTE ciphertext[], BYTE* key, int keysize, int blocks)
{
    
    // Encryption starts here:, AES_BLOCKSIZE is from aes.h
    BYTE plaintext_block[AES_BLOCK_SIZE], xor_block[AES_BLOCK_SIZE], encrypted_block[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    size_t idx, idx2;

    // Key setup
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256); // 256 is digest of SHA-256 (our key)

    // TODO: Check if padding worked
    if(plaintext.size()%AES_BLOCK_SIZE == 0)
    {
        // Main Loop
        // Transfer over IV to buffer
        
        memcpy(iv_buf, IV, AES_BLOCK_SIZE);
                
        // Start at 1 because IV is first block
        for (idx = 0; idx < blocks; idx++) {
            memcpy(plaintext_block, &plaintext[idx * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
            for (idx2 = 0; idx2 < AES_BLOCK_SIZE; idx2++) {
                xor_block[idx2] = iv_buf[idx2] ^ plaintext_block[idx2];
            }
            aes_encrypt(xor_block, encrypted_block, key_schedule, 256);
            memcpy(&ciphertext[(idx+1) * AES_BLOCK_SIZE], encrypted_block, AES_BLOCK_SIZE);
		    memcpy(iv_buf, encrypted_block, AES_BLOCK_SIZE);
             
        }
        // Append the IV to the beginning of final ciphertext
        memcpy(&ciphertext[0], IV, AES_BLOCK_SIZE);

    }
    else {
        return 1;
    }
    // Check if the length is as expected, if bad return 1 (error)
    
    return 0;
}

int decrypt_cbc(const BYTE* ciphertext, std::vector<BYTE> &decrypted_plaintext, BYTE* key, int keysize, int blocks)
{
    // Key setup
    WORD key_schedule[60];
    BYTE iv_buf[AES_BLOCK_SIZE], cipher_block[AES_BLOCK_SIZE], xor_block[AES_BLOCK_SIZE], decrypted_block[AES_BLOCK_SIZE];
    
    aes_key_setup(key, key_schedule, 256);
    
    // Extract IV from ciphertext
    memcpy(iv_buf, &ciphertext[0], AES_BLOCK_SIZE);
    
    // Decrypt the ciphertext, Ciphertext size minus an IV

    // MAIN LOOP
    // XOR decrypted block and IV
    for (int idx2 = 1; idx2 < blocks+1; idx2++)
    {
        memcpy(cipher_block, &ciphertext[idx2 * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        
        aes_decrypt(cipher_block, decrypted_block, key_schedule, 256);
        for (int idx2 = 0; idx2 < AES_BLOCK_SIZE; idx2++) {
            xor_block[idx2] = iv_buf[idx2] ^ decrypted_block[idx2];
        }
        std::cout<<"decrypted_plaintext size - "<<decrypted_plaintext.size()<<std::endl;
        for(size_t i = 0; i <AES_BLOCK_SIZE; i++)
        {
            decrypted_plaintext.push_back(xor_block[i]);
        }
        std::cout<<"decrypted_plaintext size 2- "<<decrypted_plaintext.size()<<std::endl;
        memcpy(iv_buf, cipher_block, AES_BLOCK_SIZE);
    }
    
    // TODO: Write unpadded plaintext
    unpad_cbc(decrypted_plaintext);
    return 0;
}

// Use this function to read sample_len to get cryptographically secure random stuff into sampled_bits
int sample_urandom(BYTE sampled_bits[], int sample_len)
{
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
    if(urandom.is_open())
    {
        for(int i = 0; i < sample_len; i++)
        {
            BYTE random_value; //Declare value to store data into
            size_t size = sizeof(random_value); //Declare size of data

            if(urandom) //Check if stream is open
            {
                urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
                if(urandom) //Check if stream is ok, read succeeded
                {
                    sampled_bits[i] = random_value;
                }
                else //Read failed
                {
                    std::cerr << "Failed to read from /dev/urandom" << std::endl;
                    return 1;
                }
            }
        }
    }
    else
    {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return 1;
    }

    urandom.close(); //close stream
    return 0;
}


void hash_sha256(const BYTE * input, BYTE * output, int in_len)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, in_len);
    sha256_final(&ctx, output);
}

// TODO: Update final hash
// Iterate Hashing your password 10,000+ times. Store output in final_hash
void iterate_sha256(std::string password, BYTE* final_hash, int rounds)
{
	unsigned char hash[SHA256_BLOCK_SIZE];

    // Convert password into BYTE array of chars
    BYTE password_bytes[password.length()+1];
    for(int i = 0; i < password.length(); i++)
    {
        password_bytes[i] = password[i];
    }
    password_bytes[password.length()] = '\0';

    // Iteratively hash 10k times
    // First time needs to hash variable length password_bytes
    
    hash_sha256(password_bytes, hash, password.length()+1);
    
    // Other 10,000 times hashes buffer (32 bytes)
    for (size_t i = 0; i < 10000; i++)
    {
        
        hash_sha256(hash, final_hash, SHA256_BLOCK_SIZE);
    }
    
    // Update the final hash

}

void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
              << "<function> can be: list, add, extract, delete.\n"
              << "Options:\n"
              << "\t-h, --help\t\t Show this help message.\n"
              << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
              << std::endl; 
}

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

void print_hex(const std::vector<BYTE> byte_arr)
{
    for(int i = 0; i < byte_arr.size(); i++)
    {
        printf("%.2X", byte_arr[i]);
    }
}

int read_file()
{
    std::string filename("test.txt");
    std::vector<BYTE> bytes;
    char byte = 0;
    std::ifstream input_file(filename);

    if(!input_file.is_open())
    {
        std::cerr<<"Could not open the file!"<<filename<<" "<<std::endl;
        return EXIT_FAILURE;
    }

    while(input_file.get(byte))
    {
        bytes.push_back(byte);
    }
    std::copy(bytes.begin(), bytes.end(), 
            std::ostream_iterator<char>(std::cout, ""));
    std::cout<<std::endl;
    input_file.close();
    return EXIT_SUCCESS;

}

std::vector<std::string> GetFileNames(int argc, char* argv[])
{
    std::vector<std::string> files;

    if(argc > 5 and strcmp(argv[2], "-p")==0)
    {
        std::cout<<"true";
        
        int file1 = 5;

        while(file1 < argc)
        {
            std::cout<<file1<<std::endl;
            
            if(files.end() != std::find(files.begin(), files.end(), argv[file1]))
            {
                std::cerr<<"File "<<argv[file1]<<" added twice."<<std::endl;
            }
            else{
                files.push_back(argv[file1]);
                file1++;
            }
            

        }
    }
    return files;
}

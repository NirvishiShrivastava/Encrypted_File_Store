#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <iterator>
#include <algorithm>
using std::string;
using std::ifstream; 
using std::ostringstream;

// Create error.txt, place your error message, and this will exit the program.
void die(const std::string error) 
{
	std::ofstream new_error_file("error.txt", std::ios::out | std::ios::binary | std::ios::app);
	if(!new_error_file.is_open()) {
        	std::cerr << "Could not write to error.txt" << std::endl; 
	}
	new_error_file << error << std::endl;
	new_error_file.close();
	exit(1);
}


int read_old_hmac(char* archivename, BYTE* file_mac)
{
    int archive_len, message_len;
    // string filedata;
    int pos=0;
    BYTE* array;
    int mac_len =0;
    std::vector<BYTE> hmac_str;
    std::ifstream archive_name(archivename, std::ios_base::binary);
    int i = 0, j = 0;
    char iterc;
    string break_str = "";

	int length;
	if (!archive_name.bad()) {
		length = archive_name.rdbuf()->pubseekoff(0, std::ios_base::end);
		array = new BYTE[length];
		archive_name.rdbuf()->pubseekoff(0, std::ios_base::beg);
		archive_name.read((char*)array, length);
		archive_name.close();
	}
    
    for(int i = 0; i < length; i++)
    {
        if (array[i] == '<' || array[i] == '>' || array[i] == '*' || array[i] == '&') 
        {
            break_str += array[i];
        } 
        else 
        {
            break_str = "";
        }
        if (break_str.compare("<*&>") == 0) break;
        mac_len++;
        hmac_str.push_back(array[i]);
    }
    std::vector<BYTE>::iterator it_beg, it_end;
    it_beg = hmac_str.end()-3;
    it_end = hmac_str.end();
    hmac_str.erase(it_beg, it_end);

    for(int i = 0; i < mac_len; i++)
    {
        memcpy(file_mac,&hmac_str[0],hmac_str.size());
    }
    int ret = hmac_str.size();
    hmac_str.clear();
    return SHA256_BLOCK_SIZE;
    

}

int compute_new_hmac(char* archivename, BYTE* out_tag, const BYTE* key)
{
    int archive_len, message_len;
    string filedata;
    int pos=0;
	std::vector<std::string> filedata_vector;
    // I/O: Open old archivename

    BYTE* array;
    int mac_len =0;
    std::vector<BYTE> hmac_q;
    std::ifstream archive_name(archivename, std::ios_base::binary);
    int i = 0, j = 0;
    char iterc;
    string break_str = "";

	int length;
	if (!archive_name.bad()) {
		length = archive_name.rdbuf()->pubseekoff(0, std::ios_base::end);
		array = new BYTE[length];
		archive_name.rdbuf()->pubseekoff(0, std::ios_base::beg);
		archive_name.read((char*)array, length);
		archive_name.close();
	}
    
    for(int i = 0; i < length; i++)
    {
        if (array[i] == '<' || array[i] == '>' || array[i] == '*' || array[i] == '&') 
        {
            break_str += array[i];
        } 
        else 
        {
            break_str = "";
        }
        if (break_str.compare("<*&>") == 0) break;
        mac_len++;
        hmac_q.push_back(array[i]);
    }
    
    if(hmac_q.size() == length)
    {
        hmac(&hmac_q[0], key, out_tag, hmac_q.size(), SHA256_BLOCK_SIZE);

    }
    else
    {
        int hmac_q_len = hmac_q.size();
        hmac_q.clear();
        for(int i = hmac_q_len+1; i<length; i++)
        {
            hmac_q.push_back(array[i]);
        }
        hmac(&hmac_q[0], key, out_tag, hmac_q.size(), SHA256_BLOCK_SIZE);
    }

    archive_name.close();
    filedata_vector.clear();
    hmac_q.clear();
    return SHA256_BLOCK_SIZE;
}

int verify_hmacs(char* archivename, const BYTE* key)
{
    BYTE* new_hmac = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);
    BYTE* old_hmac = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);

    int l1 = compute_new_hmac(archivename, new_hmac, key);

    int len = read_old_hmac(archivename, old_hmac);

    int res = memcmp (new_hmac, old_hmac, len);

    if(res == 0)
    {
        return 1;
    }

    return 0; 
}


int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len)
{
    // Pad key with 32 bytes to make it 64 bytes long
    BYTE padded_key[64], ipad[64], opad[64], ipad_hash[32], opad_hash[32];

    memset(ipad_hash, 0, 32);
    memset(opad_hash, 0, 32);

    // Key padding
    memset(padded_key, 0, 64);
    memcpy(padded_key, key, key_len);

    // Inner padding, 64 Bytes
    memset(ipad, 0x36, 64);

    // Outer Padding, 64 Bytes
    memset(opad, 0x5C, 64);

    /** HMAC = H((K+ XOR opad) concatenated with H((K+ XOR ipad) concatenated with M)) **/
    // Concatenate ipad and opad section: (o_key_pad || H(i_key_pad || m))
    // First, concatenate i_key_pad and message, then hash
    for(int i = 0; i < 64; i++)
    {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }

    // (K+ XOR ipad) concatenated with M
    BYTE* i_key_pad = (BYTE *) malloc((message_len + 64) * sizeof(BYTE));
    memcpy(i_key_pad, ipad, 64);
    memcpy(i_key_pad+64, message, message_len);
    
    // Hash i_key_pad
    hash_sha256(i_key_pad, ipad_hash, message_len+64);

    // Second, concatenate the o_key_pad and H(i_key_pad || m)
  //BYTE* o_key_pad = (BYTE *) malloc((SHA256_BLOCK_SIZE + 64) * sizeof(BYTE));
    BYTE* o_key_pad = (BYTE *) malloc(128);
    memset(o_key_pad,0,128);
    memcpy(o_key_pad, opad, 64);
    memcpy(o_key_pad+64, ipad_hash, SHA256_BLOCK_SIZE);

    // Finally, hash the entire thing
    hash_sha256(o_key_pad, opad_hash, 128);
    memcpy(out_tag, opad_hash, SHA256_BLOCK_SIZE);

    free(i_key_pad);
    free(o_key_pad);
    return 0;

}

int verify_archive_exists(char* archivename)
{
    std::fstream archive_name(archivename);

    archive_name.seekg(0, archive_name.end);
    int archive_len = archive_name.tellg();
    if (archive_len <= 0)
    {
        return 0;
    }
    return 1;

}


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

    // XOR decrypted block and IV
    for (int idx2 = 1; idx2 < blocks+1; idx2++)
    {
        memcpy(cipher_block, &ciphertext[idx2 * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        
        aes_decrypt(cipher_block, decrypted_block, key_schedule, 256);
        for (int idx2 = 0; idx2 < AES_BLOCK_SIZE; idx2++) {
            xor_block[idx2] = iv_buf[idx2] ^ decrypted_block[idx2];
        }
        for(size_t i = 0; i < AES_BLOCK_SIZE; i++)
        {
            decrypted_plaintext.push_back(xor_block[i]);
        }
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


std::vector<std::string> GetFileNames(int argc, char* argv[])
{
    std::vector<std::string> files;

    if(argc > 5 and strcmp(argv[2], "-p")==0)
    {
        
        int file1 = 5;

        while(file1 < argc)
        {
            
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

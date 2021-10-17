#ifndef CSTORE_UTILS
#define CSTORE_UTILS
#include <vector>
#include <string>
#include "crypto_lib/aes.h"

#define SHA256_ITERS 10000
#define HMAC_BLOCKSIZE 64

void die (std::string error);

void show_usage(std::string name);

int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len);

int read_old_hmac(char* archivename, BYTE* file_mac);

int compute_new_hmac(char* archivename, BYTE* out_tag, const BYTE* key);

int encrypt_cbc(std::vector<BYTE> plaintext, const BYTE* IV, BYTE ciphertext[], BYTE key[], int keysize, int blocks);

int decrypt_cbc(const BYTE* ciphertext, std::vector<BYTE> &decrypted_plaintext, BYTE* key, int keysize, int blocks);

int sample_urandom(BYTE sampled_bits[], int sample_len);

std::vector<BYTE> pad_cbc(std::vector<BYTE> data);

std::vector<BYTE> unpad_cbc(const BYTE* padded_data, int len);

void sample_random(char * buf, int sample_bytes);

void hash_sha256(const BYTE * input, BYTE * output, int in_len);

void iterate_sha256(std::string password, BYTE* final_hash, int rounds);

void print_hex(const BYTE* byte_arr, int len);

void print_hex(const std::vector<BYTE> byte_arr);

std::vector<std::string> GetFileNames(int argc, char* argv[]);

int verify_archive_exists(char* archivename);

int verify_hmacs(char* archivename, const BYTE* key);


#endif

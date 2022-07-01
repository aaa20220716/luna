#ifndef _AES_CBC128_H_
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <openssl/aes.h>
#include <stddef.h>
 
#define _AES_CBC256_H_
#define USER_KEY_LENGTH 16
#define IVEC_LENGTH     16
#define AES_BLOCK_SIZE  16
#define BITS_LENGTH   (USER_KEY_LENGTH * 8)
#define BLOCK_SIZE 16
class AES_CBC128 {
public:
     AES_CBC128();
     virtual ~AES_CBC128();
     // CBC Mode Encrypt
     bool AES_CBC128_Encrypt(const unsigned char *in, unsigned char *out, unsigned char* user_key, unsigned char* user_iv, size_t length);
     // CBC Mode Decrypt
     bool AES_CBC128_Decrypt(const unsigned char *in, unsigned char *out, unsigned char* user_key, unsigned char* user_iv, size_t length);
};
#endif   // _AES_CBC256_H_
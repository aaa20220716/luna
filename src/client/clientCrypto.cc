#ifndef _AES_CBC128_H_
# include "clientCrypto.hh"
#endif
 
AES_CBC128::AES_CBC128() {
    
}
AES_CBC128::~AES_CBC128() {
 
}

bool AES_CBC128::AES_CBC128_Encrypt(const unsigned char *in, unsigned char *out, unsigned char *user_key, unsigned char * user_iv, size_t length) {
 
    if (0 != (length % AES_BLOCK_SIZE)) {
        printf("%s\n", "the length is not multiple of AES_BLOCK_SIZE(16bytes)");
        return false;
    }
    unsigned char ivec [IVEC_LENGTH];
    memcpy(ivec, user_iv, IVEC_LENGTH);
    AES_KEY key;
    if (AES_set_encrypt_key(user_key, BITS_LENGTH, &key) < 0) {
    	return false;
    } 
    AES_cbc_encrypt(in, out, length, &key, ivec, AES_ENCRYPT);
    return true;
}
 
bool AES_CBC128::AES_CBC128_Decrypt(const unsigned char *in, unsigned char *out, unsigned char *user_key, unsigned char * user_iv, size_t length) {
 
    if (0 != (length % AES_BLOCK_SIZE)) {
        printf("%s\n", "the length is not multiple of AES_BLOCK_SIZE(16bytes)");
        return false;
    }
    unsigned char ivec [IVEC_LENGTH];
    memcpy(ivec, user_iv, IVEC_LENGTH);
    AES_KEY key;
    
    if (AES_set_decrypt_key(user_key, BITS_LENGTH, &key) < 0) {
    	printf("%s\n", "get the key error");
    	return false;
    } else {
    	printf("%s\n", "get the key successful");
    }
 
    AES_cbc_encrypt(in, out, length, &key, ivec, AES_DECRYPT);
    return true;
}
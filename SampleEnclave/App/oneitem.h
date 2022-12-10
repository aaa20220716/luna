#pragma once
#include "AES.h"

#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

using namespace std;

class state{
  public:
    int aw;
    int nw;
    //state(){}
    ~state(){}
    state(int a, int b) : aw(a), nw(b){}

    bool operator==(const state&t)const{
      return this->aw == t.aw;
  }
};

std::unordered_map<std::string, std::string> Tmap;
std::unordered_map<std::string, std::string> Vmap;

size_t get_file_size(char *filename);
bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize)
bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset);
void get_kv_ivv(std::string kV, std::string ivV, std::string& secret);
void get_k_iv(std::string kT, std::string ivT, std::string kV, std::string ivV, std::string& secret);
void gen_enc_secret(std::string secret, std::string& enc_enc_secret);
std::string aes_128_gcm_encrypt(unsigned char* aes_key, unsigned char * iv, const std::string& message);
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_decode(std::string const& encoded_string);
void GenuT(std::string keyw, int aw, std::string &h3, std::string &h4);
void GeneT(int ind, std::string h2, std::string& eT);
void ClientSt_update(std::string w, std::unordered_map<std::string, state>& client_st, bool flag);
void clientst_show(std::unordered_map<std::string, state>& client_st);
void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen);
std::string EncryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc);
std::string DecryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc);
void get_eV(std::string xV, std::string& eV);
void delete_idx_val(std::string uT, std::string uV);
void get_from_edb(std::string map_name, char* xuT, std::string& xeT);
std::string Genkw(unsigned char *user_key, unsigned char *user_iv, std::string w);
void store_idx_val(std::string uT, std::string eT, std::string uV, std::string ev, int ind, std::string enc);
/*
 Copyright (c) 2022 Siyi Lv

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef UTILS_HH
#define UTILS_HH

#include <string>
#include <sys/time.h>
#include <unordered_map>
#include "clientCrypto.hh"
#include <ctype.h>
#include "hash.hh"
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cmath>
#include <cstdint>
#include <chrono>
#include <sample_libcrypto/sample_libcrypto.h>

static const std::string digits = "0123456789abcdef";

class state{
  public:
    int aw;
    int nw;
    ~state(){}
    state(int a, int b) : aw(a), nw(b){}

    bool operator==(const state&t)const{
      return this->aw == t.aw;
  }
};

char *randstr(char *str, const int len);
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_decode(std::string const& encoded_string);
std::string EncryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc);
std::string DecryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc);
void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen);
std::string GenKind(int ind);
std::string Genkw(unsigned char *user_key, unsigned char *user_iv, std::string w);
void GenuT(std::string keyw, int aw, std::string &h3, std::string &h4);
void GeneT(int ind, std::string h2, std::string& eT);
void ClientSt_update(std::string w, std::unordered_map<std::string, state>& client_st, bool flag);
void clientst_show(std::unordered_map<std::string, state>& client_st);
void GetRecords(std::string datafile, std::vector<std::string>& vals);
void GetfileRecords(std::string datafile, std::vector<int>& inds, std::vector<std::string>& kws);
void get_k_iv(std::string kT, std::string ivT, std::string kV, std::string ivV, std::string& secret);
void get_kv_ivv(std::string kV, std::string ivV, std::string& secret);
void gen_enc_secret(std::string session_key, std::string secret, std::string& enc_enc_secret);
std::string aes_128_gcm_encrypt(unsigned char* aes_key, unsigned char * iv, const std::string& message);
void get_pt(unsigned char* user_key, std::string xct, std::vector<std::string>& pt);
std::string hex_to_string(const uint8_t* array, const size_t& len = 32);
void convert_endian(uint8_t* array, const size_t& len = 32);
uint64_t timeSinceEpochMillisec();
#endif
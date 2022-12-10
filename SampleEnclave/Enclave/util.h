#ifndef ENCLAVE_UTILS_HH
#define ENCLAVE_UTILS_HH
#include "AES.h"
//#include "Base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <cstring>
#include <random>
#include <vector>
#include <unordered_map>
#include "hash.h"
#include <enclave/enclave_crypto_manager.hh>

using namespace std;

static const std::string digits = "0123456789abcdef";
/** @addtogroup String concatenation helpers with arbitrary elements.
 *
 *  @{
 */


template <typename T>
/*inline std::string to_string(T&& val) {
  if constexpr (std::is_arithmetic<T>::value) {
    return std::to_string(val);
  } else if constexpr (std::is_same<std::decay_t<T>, const char*>::value) {
    return std::string(val);
  }
}*/

inline std::string strcat_helper(const std::string& string) { return string; }

// Concatenate a list of strings into a single string.
// Example: strcat({"hello", "world"}) -> "helloworld"
template <class T, class... Args>
inline std::string strcat_helper(const std::string& string, T&& val,
                                 Args&&... args) {
  return strcat_helper(string + to_string(std::forward<T>(val)),
                       (std::forward<Args>(args))...);
}

template <class... Args>
inline std::string strcat(Args&&... args) {
  std::string string;
  return strcat_helper(string, (std::forward<Args>(args))...);
}

/** @} */

/**
 * @brief Cast an unsigned char array to hexical std::string.
 *
 * @param array
 * @param len
 * @return std::string
 */
std::string hex_to_string(const uint8_t* array, const size_t& len = 32);

/**
 * @brief Cast a hexcial string to char array.
 *
 * @param in
 * @param out
 */
void string_to_hex(const std::string& in, uint8_t* out);

/**
 * @brief A debug function for printing the buffer inside the enclave.
 *
 * @param fmt
 * @param ...
 */
void printf(const char* fmt, ...);

/**
 * @brief A special interface for std::string type.
 *
 * @param str
 * @param hex
 */
void sprintf(const std::string& str, bool hex = false);

/**
 * @brief Safe free the memory.
 * 
 * @param ptr 
 */
void safe_free(void* ptr);

void band(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out);

void bor(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out);

void bneg(const uint8_t* lhs, uint8_t* out);

std::string GenKind(int ind);
void GenuV(std::string ind, std::string keyInd, std::string &h1, std::string &h2);
void GeneV(std::string w, std::string aw, std::string h4, std::string& eV);

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_decode(std::string const& encoded_string);

void parse_add_state(std::string cst, std::string& w, std::string& ind, std::string&aw, std::string& kV, std::string& ivV);

void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen);

void I_to_str(std::unordered_map<std::string, int> I, std::string& Istr);
void str_to_Map(std::string str, std::unordered_map<std::string, int>& V);
void str_to_Vec(std::string str, std::vector<std::string>& res1);

void Decrypt(std::shared_ptr<EnclaveCryptoManager> sse_crypto_manager, char* enc_st, int data_size, std::string& cst);
void parse_del_state(std::string cst, std::string& w, std::string& ind, std::string& kT, std::string& ivT, std::string& kV, std::string& ivV);
void parse_eV(char *eV, std::vector<std::string>& vec_eV);
void gen_h4(std::string kind, int cnt, std::vector<std::string>& vec_h4);
void GenuT(std::string keyw, std::string dind, std::string &h3);
void parse_search_state(std::string enc_st, std::string& w, std::string& nw, std::string& kw);
void randstr(std::string& s, const int len);
uint32_t untrusted_uniform_random(const uint32_t& lower,
                                  const uint32_t& upper);
void parse_Num(std::string sNum, int *Num, int inw);
void gen_h2(std::string keyw, int i, std::string& h2);



#endif
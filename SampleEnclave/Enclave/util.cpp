#pragma once
#include "util.h"
#include "Base64.h"
using namespace std;


void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  }
}

std::string hex_to_string(const uint8_t* array, const size_t& len) {
  std::string ans;

  for (size_t i = 0; i < len; i++) {
    // To hex.
    uint8_t num = array[i];
    ans += digits[num & 0xf];
    ans += digits[num >> 4];
  }

  return ans;
}

void string_to_hex(const std::string& in, uint8_t* out) {
  // The output length is specified by in.size().
  uint32_t j = 0;
  for (uint32_t i = 0; i < in.size(); i += 2) {
    if (std::isalpha(in[i])) {
      out[j] = (10 + in[i] - 'a') << 4;
    } else {
      out[j] = (in[i] - '0') << 4;
    }

    if (std::isalpha(in[i + 1])) {
      out[j] += (10 + in[i + 1] - 'a');
    } else {
      out[j] += (in[i + 1] - '0');
    }
    j++;
  }
}

void printf(const char* fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_printf(buf);
}

void sprintf(const std::string& str, bool hex) {
  if (hex) {
    printf("%s", hex_to_string((const uint8_t*)str.data(), str.size()).data());
  } else {
    printf("%s", str.data());
  }
}

void band(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out) {
  for (size_t i = 0; i < 32; i++) {
    out[i] = lhs[i] & rhs[i];
  }
}

void bor(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out) {
  for (size_t i = 0; i < 32; i++) {
    out[i] = lhs[i] | rhs[i];
  }
}

void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN] = {0};
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, md);
	memcpy(dest, md, SHA256_DIGESTLEN);
}

void GenuV(std::string ind, std::string keyInd, std::string &h1, std::string &h2) {
  unsigned char* tmplabelind = new unsigned char[SHA256_DIGESTLEN + 1];
  memset(tmplabelind, 0, SHA256_DIGESTLEN + 1);
  char *ckeyInd = new char[64];
  memset(ckeyInd, 0, 64);
  memcpy(ckeyInd, keyInd.c_str(), keyInd.length());
  char *cind = new char[10];
  memset(cind, 0, 10);
  memcpy(cind, ind.c_str(), ind.length());
	compute_hmac_ex(tmplabelind, (const uint8_t *)ckeyInd, strlen(ckeyInd), (const uint8_t *)cind, strlen(cind));
  char *ch1 = new char[17];
  char *ch2 = new char[17];
  memset(ch1, 0, 17);
  memset(ch2, 0, 17);
  memcpy(ch1, tmplabelind, 16);
  memcpy(ch2, tmplabelind + 16, 16);
  h1 = base64_encode((const unsigned char*)ch1, 16);
  h2 = base64_encode((const unsigned char*)ch2, 16);
  delete[] ch1;
  delete[] ch2;
  delete[] tmplabelind;
  delete[] ckeyInd;
  delete[] cind;
  return;
}

void GeneV(std::string w, std::string aw, std::string h4, std::string& eV) {
  int len = 16;

  std::string sh4 = base64_decode(h4);
  char *ch4 = new char[len + 1];
  memset(ch4, 0, len + 1);
  memcpy(ch4, sh4.c_str(), sh4.length());

  char *wCW = new char[len + 1];
  memset(wCW, 0, len + 1);
  std::string sign = ",";
  memset(wCW, '@', len);
  memcpy(wCW, w.c_str(), w.length());
  memcpy(wCW + w.length(), sign.c_str(), sign.length());
  memcpy(wCW + w.length() + 1, aw.c_str(), aw.length());
  

  char *ceV = new char[len + 1];
  memset(ceV, 0, len + 1);

  for(int i = 0; i < len; i ++) {
    ceV[i] = wCW[i] ^ ch4[i];
  }
  eV = base64_encode((const unsigned char*)ceV, len);
  delete[] ch4;
  delete[] wCW;
  delete[] ceV;
}

void parse_add_state(std::string cst, std::string& w, std::string& ind, std::string&aw, std::string& kV, std::string& ivV){
  std::vector<std::string> resultVec;
  std::string pattern = "*";
  char* tmpStr = strtok((char *)cst.c_str(), pattern.c_str());
  while (tmpStr != NULL)
  {
    resultVec.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  w = resultVec[0];
  ind = resultVec[1];
  aw = resultVec[2];
  kV = resultVec[3];
  ivV = resultVec[4];
}


void I_to_str(std::unordered_map<std::string, int> I, std::string& Istr) {
  std::string dot = ",";
  std::string sign = "*";
  std::string str;
  for (auto &x : I) {
		str.append(x.first);
    str.append(dot);
    str.append(std::to_string(x.second));
    str.append(sign);
	}
  char *cstr = new char[str.length() + 1];
  memset(cstr, 0, str.length() +1);
  memcpy(cstr, str.c_str(), str.length());
  Istr = cstr;

  delete[] cstr;
}

void str_to_Map(std::string str, std::unordered_map<std::string, int>& V) {
  std::vector<std::string> res1;
  
  str_to_Vec(str, res1);
  int i = 0;
  for(auto it : res1) {
    i = it.find(',', 0);
    std::string sind = it.substr(0, i);
    std::string scnt = it.substr(i+1);

    V.insert(std::make_pair((std::string)sind, (int)atoi((const char*)scnt.c_str())));
  }
}

void str_to_Vec(std::string str, std::vector<std::string>& res1) {
  std::string sign = "*";
  char *tmpStr1 = strtok((char *)str.c_str(), sign.c_str());
  while(tmpStr1 != NULL) {
    res1.push_back(std::string(tmpStr1));
    tmpStr1 = strtok(NULL, sign.c_str());
  }
}
void randstr(std::string& s, const int len)
{
  for (uint32_t j = 0; j < len; j++) {
    const uint32_t pos = untrusted_uniform_random(0, candidate.size() - 1);
    s.push_back(candidate[pos]);
  }
}
uint32_t untrusted_uniform_random(const uint32_t& lower,
                                  const uint32_t& upper) {
  if (lower == upper) {
    return lower;
  }
  std::random_device rd;
  std::mt19937 engine(rd());
  std::uniform_int_distribution<uint32_t> dist(lower, upper);
  return dist(engine);
}



void Decrypt(std::shared_ptr<EnclaveCryptoManager> sse_crypto_manager, char* enc_st, int data_size, std::string& cst){
  
  char *c_enc_st = new char[data_size + 1];
  memset(c_enc_st, 0, data_size + 1);
  memcpy(c_enc_st, enc_st, data_size);
  std::string s_enc_st = c_enc_st;

  std::string enc_cst = base64_decode(s_enc_st);
  
  const std::string sst = enc_cst;
  
  cst = sse_crypto_manager->aes_128_gcm_decrypt(sst);

  delete[] c_enc_st;
}

void parse_del_state(std::string cst, std::string& w, std::string& ind, std::string& kT, std::string& ivT, std::string& kV, std::string& ivV){
  std::vector<std::string> resultVec;
  std::string pattern = "*";
  char* tmpStr = strtok((char *)cst.c_str(), pattern.c_str());
  while (tmpStr != NULL)
  {
    resultVec.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  w = resultVec[0];
  ind = resultVec[1];
  kT = resultVec[2];
  ivT = resultVec[3];
  kV = resultVec[4];
  ivV = resultVec[5];
}

void parse_search_state(std::string cst, std::string& w, std::string& nw, std::string& kw) {
  std::vector<std::string> resultVec;
  std::string pattern = "*";
  char* tmpStr = strtok((char *)cst.c_str(), pattern.c_str());
  while (tmpStr != NULL)
  {
    resultVec.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  w = resultVec[0];
  nw = resultVec[1];
  kw = resultVec[2];
}

void parse_eV(char *eV, std::vector<std::string>& vec_eV) {
  std::string pattern = "*";
  char* tmpStr = strtok(eV, pattern.c_str());
  while (tmpStr != NULL)
  {
    vec_eV.push_back(base64_decode(std::string(tmpStr)));
    tmpStr = strtok(NULL, pattern.c_str());
  }

}

void gen_h4(std::string kind, int cnt, std::vector<std::string>& vec_h4) {
  std::string si, h1, h2,dh2;
  for (int i = 0; i < cnt; i ++){
    si = std::to_string(i);
    GenuV(si, kind, h1, h2);
    dh2 = base64_decode(h2);
    vec_h4.push_back(dh2);
  }
  
}

void GenuT(std::string keyw, std::string dind, std::string &h3) {
  char *cind = new char[10];
  memset(cind, 0, 10);
  memcpy(cind, dind.c_str(), dind.length());
  char *ckeyw = new char[64];
  memset(ckeyw, 0, 64);
  memcpy(ckeyw, keyw.c_str(), keyw.length());

  unsigned char tmplabelw[SHA256_DIGESTLEN] = {0};
  compute_hmac_ex(tmplabelw, (const uint8_t *)ckeyw, strlen(ckeyw), (const uint8_t *) cind, strlen(cind));
  char *ch3 = new char[17];
  memset(ch3, 0, 17);
  memcpy(ch3, tmplabelw, 16);
  h3 = base64_encode((const unsigned char*)ch3, 16);

  delete[] ch3;
  delete[] cind;
  delete[] ckeyw;
  return;
}
void parse_Num(std::string sNum, int *Num, int inw) {
  std::string pattern = "*";
  std::vector<std::string> vec;
  char* tmpStr = strtok((char*)sNum.c_str(), pattern.c_str());
  while (tmpStr != NULL)
  {
    vec.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  for (int i = 0 ; i < inw; i++) {
    Num[i] = atoi((char*)vec[i].c_str());
  }
}

void gen_h2(std::string keyw, int i, std::string& h2){
  std::string kw = std::to_string(i);
  char *ckw = new char[10];
  memset(ckw, 0, 10);
  memcpy(ckw, kw.c_str(), kw.length());
  char *ckeyw = new char[64];
  memset(ckeyw, 0, 64);
  memcpy(ckeyw, keyw.c_str(), keyw.length());


  unsigned char tmplabelw[SHA256_DIGESTLEN] = {0};
  compute_hmac_ex(tmplabelw, (const uint8_t *)ckeyw, strlen(ckeyw), (const uint8_t *) ckw, strlen(ckw));
  char *ch3 = new char[17];
  char *ch4 = new char[17];
  memset(ch3, 0, 17);
  memset(ch4, 0, 17);
  memcpy(ch3, tmplabelw, 16);
  memcpy(ch4, tmplabelw + 16, 16);

  h2 = ch4;

  delete[] ch3;
  delete[] ch4;
  delete[] ckeyw;
  delete[] ckw;
}


#pragma once
#include "oneitem.h"
#include "Base64.h"

using namespace std;



size_t get_file_size(char *filename)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  size_t size = (size_t)ifs.tellg();
  return size;
}
bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good())
  {
    return false;
  }
  ifs.read(reinterpret_cast<char *> (buf), bsize);
  if (ifs.fail())
  {
    return false;
  }
  return true;
}

bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ofstream ofs(filename, std::ios::binary | std::ios::out);
  if (!ofs.good())
  {
    return false;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(buf), bsize);
  if (ofs.fail())
  {
    return false;
  }

  return true;
}
void get_kv_ivv(std::string kV, std::string ivV, std::string& secret){
  std::string sign = "*";

  char* ckv = new char[17];
  memset(ckv, 0, 17);
  memcpy(ckv, kV.c_str(), 16);
  std::string skV = ckv;
  secret.append(skV);
  secret.append(sign);
  char* civV = new char[17];
  memset(civV, 0, 17);
  memcpy(civV, ivV.c_str(), 16);
  std::string sivV = civV;
  secret.append(sivV);

  delete[] ckv;
  delete[] civV;

}

std::string aes_128_gcm_encrypt(unsigned char* aes_key, unsigned char * iv, const std::string& message) {
  const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(message.data());

  size_t cipher_len = message.size() + 28;
  uint8_t* ciphertext = (uint8_t*)(malloc(cipher_len));
  memset(ciphertext, 0, cipher_len);
  sample_status_t ret = sample_rijndael128GCM_encrypt(
      (sample_aes_gcm_128bit_key_t*)aes_key, 
      plaintext, 
      message.size(),
      ciphertext + 28,
      iv,
      12, 
      NULL, 
      0,
      (sample_aes_gcm_128bit_tag_t*)(ciphertext));
  return std::string((char*)(ciphertext), cipher_len);
}

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";
 
 
static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}
 
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];
 
  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;
 
      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }
 
  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';
 
    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;
 
    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];
 
    while((i++ < 3))
      ret += '=';
 
  }
 
  return ret;
 
}
 
std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;
 
  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);
 
      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
 
      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }
 
  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;
 
    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);
 
    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
 
    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }
 
  return ret;
}

std::string EncryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc)
{
    if (strSrc.empty()){
        return NULL;
    }
    size_t length = strSrc.length();
    int block_num = length / BLOCK_SIZE + 1;
    
    char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
    strcpy(szDataIn, strSrc.c_str());
 
    int k = length % BLOCK_SIZE;
    int j = length / BLOCK_SIZE;
    int padding = BLOCK_SIZE - k;
    for (int i = 0; i < padding; i++)
    {
        szDataIn[j * BLOCK_SIZE + k + i] = padding;
    }
    szDataIn[block_num * BLOCK_SIZE] = '\0';
 
    char *szDataOut = new char[block_num * BLOCK_SIZE + 1];
    memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);
    
    AES_CBC128 aes;
    aes.AES_CBC128_Encrypt((const unsigned char *)szDataIn, (unsigned char *)szDataOut, (unsigned char*)user_key, (unsigned char*)user_iv, block_num * BLOCK_SIZE);
    std::string str = base64_encode((unsigned char*) szDataOut,
            block_num * BLOCK_SIZE);
    delete[] szDataIn;
    delete[] szDataOut;
    return str;
}

std::string DecryptionAES(unsigned char* user_key, unsigned char* user_iv, std::string& strSrc)
{
    std::string strData = base64_decode(strSrc);
    size_t length = strData.length();
    
    char *szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length+1);
    
    char *szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length+1);
 
    AES_CBC128 aes;
    aes.AES_CBC128_Decrypt((const unsigned char*)szDataIn, 
                            (unsigned char*)szDataOut, 
                            (unsigned char*)user_key, 
                            (unsigned char*)user_iv, 
                            length);
 
    if (0x00 < szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    char *res = new char[length + 1];
    int i;
    for(i = 0; szDataOut[i] != '$' && szDataOut[i] != '\0'; i++)
    {
        res[i] = szDataOut[i];
    }
    res[i] = '\0';
    std::string strDest(res);
    delete[] szDataIn;
    delete[] szDataOut;
    delete[] res;
    return strDest;
}

void gen_enc_secret(std::string secret, std::string& enc_enc_secret) {
  unsigned char* aes_key = new unsigned char[17];
  unsigned char* iv = new unsigned char [13];

  std::string key = "abcdefghijklmnopqrstuvwxyz12";

  memset(aes_key, 0, 17);
  memset(iv, 0, 13);
  memcpy(aes_key, key.c_str(), 16);
  memcpy(iv, key.c_str() + 16, 12);

  std::string enc_secret = aes_128_gcm_encrypt(aes_key, iv, (const std::string)secret);
  enc_enc_secret = base64_encode((const unsigned char*)enc_secret.c_str(), enc_secret.length());
  
  delete[] aes_key;
  delete[] iv;
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

void GenuT(std::string keyw, int aw, std::string &h3, std::string &h4) {
  std::string kw = std::to_string(aw);
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
  h3 = base64_encode((const unsigned char*)ch3, 16);
  h4 = base64_encode((const unsigned char*)ch4, 16);

  delete[] ch3;
  delete[] ch4;
  delete[] ckeyw;
  delete[] ckw;
  return;
}

void GeneT(int ind, std::string h2, std::string& eT) {
  std::string sind = std::to_string(ind);
  char* cind = new char[17];
  memset(cind, 0, 17);
  memset(cind, '*', 16);
  memcpy(cind, sind.c_str(), sind.length());

  std::string sh2 = base64_decode(h2);
  char *ch2 = new char[17];
  memset(ch2, 0, 17);
  memcpy(ch2, sh2.c_str(), sh2.length());

  char *ceT = new char[17];
  memset(ceT, 0, 17);

  for(int i = 0; i < 16; i++) {
    ceT[i] = ch2[i] ^ cind[i];
  }
  eT = base64_encode((const unsigned char*)ceT, 16);
  delete[] cind;
  delete[] ch2;
  delete[] ceT;
}

void ClientSt_update(std::string w, std::unordered_map<std::string, state>& client_st, bool flag){
  std::unordered_map<std::string, state>::iterator it = client_st.find(w);
  int aw, nw;
  if (flag) {
    aw = ((client_st.find(w))->second).aw + 1;
    nw = ((client_st.find(w))->second).nw + 1;
  } else {
    aw = ((client_st.find(w))->second).aw + 1;
    nw = ((client_st.find(w))->second).nw - 1;
  }
  
  it = client_st.erase(it);

  state newst(aw, nw);
  client_st.insert(std::make_pair(w, newst));
}

void clientst_show(std::unordered_map<std::string, state>& client_st) {
  for (auto &x : client_st) {
		LOG(plog::info) << "w = " << x.first << ", aw = " << x.second.aw << ",nw = " <<x.second.nw;
	}
}

void get_k_iv(std::string kT, std::string ivT, std::string kV, std::string ivV, std::string& secret){
  std::string sign = "*";
  char* ckt = new char[17];
  memset(ckt, 0, 17);
  memcpy(ckt, kT.c_str(), 16);
  std::string skT = ckt;
  secret.append(skT);
  secret.append(sign);
  char* civT = new char[17];
  memset(civT, 0, 17);
  memcpy(civT, ivT.c_str(), 16);
  std::string sivT = civT;
  secret.append(sivT);
  secret.append(sign); 

  char* ckv = new char[17];
  memset(ckv, 0, 17);
  memcpy(ckv, kV.c_str(), 16);
  std::string skV = ckv;
  secret.append(skV);
  secret.append(sign);
  char* civV = new char[17];
  memset(civV, 0, 17);
  memcpy(civV, ivV.c_str(), 16);
  std::string sivV = civV;
  secret.append(sivV);

  delete[] ckv;
  delete[] civV;
  delete[] ckt;
  delete[] civT;
}

void get_eV(std::string xV, std::string& eV) {
  std::vector<std::string> vec_xV;
  std::string pattern = "*";
  char* tmpStr = strtok((char *)xV.c_str(), pattern.c_str());
  while (tmpStr != NULL)
  {
    vec_xV.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  
  for (auto it : vec_xV) {
    std::string sub_eV = Vmap.find(it)->second;
    eV.append((std::string)sub_eV);
    eV.append(sign);
  }
  
  delete[] sub_eV;
}

void delete_idx_val(std::string uT, std::string uV) {
  std::unordered_map<std::string, std::string>::iterator Tit = Tmap.find(uT);
  Tit = Tmap.erase(Tit);

  std::unordered_map<std::string, std::string>::iterator Vit = Vmap.find(uV);
  Vit = Tmap.erase(Vit);
}

void get_from_edb(std::string map_name, char* xuT, std::string& xeT) {
  std::vector<std::string> vec_xT;
  std::string pattern = "*";
  char* tmpStr = strtok(xuT, pattern.c_str());
  while (tmpStr != NULL)
  {
    vec_xT.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  if (!map_name.compare("Tmap")) {
    for (auto it : vec_xT) {
      std::string sub_eT = Tmap.find(it)->second;
      xeT.append((std::string)sub_eT);
      xeT.append(sign);
    }
  } else if (!map_name.compare("Vmap")) {
    for (auto it : vec_xT) {
      std::string sub_eT = Tmap.find(it)->second;
      xeT.append((std::string)sub_eT);
      xeT.append(sign);
    }
  }
  
  delete[] sub_eT;
}

std::string Genkw(unsigned char* user_key, unsigned char* user_iv, std::string w) {
  std::string kw = aes_128_gcm_encrypt(user_key, user_iv, w);
  return kw;
}

void store_idx_val(std::string uT, std::string eT, std::string uV, std::string eV){
    Tmap.insert(map<string, string>::value_type(uT, eT));
    Vmap.insert(map<string, string>::value_type(uV, eV));
}
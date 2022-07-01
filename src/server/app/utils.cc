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
#include <algorithm>
#include <iostream>
#include <random>
#include <memory>

#include <gzip/compress.hpp>
#include <gzip/decompress.hpp>
#include <app/server_runner.hh>
#include <plog/Log.h>

#include <enclave/enclave_u.h>
#include <utils.hh>
#include <configs.hh>

extern std::unique_ptr<Server> server_runner;

void ocall_write_slot(const char* slot_finger_print, const uint8_t* data,
                      size_t data_len) {
  LOG(plog::debug) << "The fingerprint for the slot is: " << slot_finger_print;

  const char* data_ptr = reinterpret_cast<const char*>(data);
  std::string compressed_data = gzip::compress(data_ptr, data_len);
  server_runner->store_compressed_slot(slot_finger_print, compressed_data);

  LOG(plog::debug) << "Compressed: "
                   << sgx_sse::hex_to_string((uint8_t*)compressed_data.data(),
                                              compressed_data.size());
}

void ocall_printf(const char* message) {
  LOG(plog::debug) << "The fingerprint for the slot is: " << message;
}
void ocall_trans(char *ss, int ssl){
  char *css = new char[ssl + 1];
  memset(css, 0, ssl + 1);
  memcpy(css, ss, ssl);
  std::string out = css;
  LOG(plog::info) << "from enclave, " << out;

  delete[] css;
}

void ocall_exception_handler(const char* err_msg) {
  throw std::runtime_error(err_msg);
}

size_t ocall_read_slot(const char* slot_finger_print, uint8_t* data,
                       size_t data_len) {
  LOG(plog::debug) << "The fingerprint for the slot is: " << slot_finger_print;

  bool is_in_memory = server_runner->is_in_storage(slot_finger_print);

  if (is_in_memory) {
    std::string compressed_data =
        server_runner->get_compressed_slot(slot_finger_print);
    const char* data_ptr =
        reinterpret_cast<const char*>(compressed_data.data());
    std::string decompressed_data =
        gzip::decompress(data_ptr, compressed_data.size());

    const size_t decompressed_size = decompressed_data.size();
    memcpy(data, decompressed_data.data(), decompressed_size);
    return decompressed_size;
  } else {
    LOG(plog::debug) << "Slot not found in memory.";

    return 0;
  }
}

namespace sgx_sse {
std::vector<std::string> generate_random_strings(const uint32_t& number,
                                                 const uint32_t& length) {
  std::vector<std::string> ans;

  for (uint32_t i = 0; i < number; i++) {
    std::string s;
    for (uint32_t j = 0; j < 32; j++) {
      const uint32_t pos = untrusted_uniform_random(0, candidate.size() - 1);
      s.push_back(candidate[pos]);
    }
    ans.push_back(s);
  }

  return ans;
}

std::vector<std::string> get_data_from_file(std::ifstream* const file) {
  LOG(plog::debug) << "Reading data from file is started!";
  std::vector<std::string> ans;
  while (!(*file).eof()) {
    std::string s;
    std::getline(*file, s);
    ans.push_back(s);
  }
  LOG(plog::debug) << "Reading data from file is finished!";

  return ans;
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

void print_error_message(sgx_status_t ret)
{
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if(ret == sgx_errlist[idx].err) {
      if(NULL != sgx_errlist[idx].sug)
          LOG(plog::info) << sgx_errlist[idx].sug;
      LOG(plog::info) << sgx_errlist[idx].msg;
    break;
    }
  }
    
  if (idx == ttl)
  LOG(plog::info) << "Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n";
}

size_t get_file_size(char *filename)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    LOG(plog::error) << "Failed to open the file \"" 
                      << filename;
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
    LOG(plog::error) << "Failed to open the file \"" 
                      << filename;
    return false;
  }
  ifs.read(reinterpret_cast<char *> (buf), bsize);
  if (ifs.fail())
  {
    LOG(plog::error) << "Failed to read the file \"" 
                      << filename;
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
    LOG(plog::error) << "Failed to open the file \"" 
                      << filename;
    return false;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char*>(buf), bsize);
  if (ofs.fail())
  {
    LOG(plog::error) << "Failed to write the file \"" 
                      << filename;
    return false;
  }

  return true;
}


int init_enclave(sgx_enclave_id_t* const id) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_launch_token_t launch_token = {0};
  int updated = 0;

  ret = sgx_create_enclave(enclave_path.c_str(), 1, &launch_token, &updated, id, nullptr);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    return -1;
  }
  return 0;
}

std::string hex_to_string(const uint8_t* array, const size_t& len) {
  std::string ans;

  for (size_t i = 0; i < len; i++) {
    uint8_t num = array[i];
    ans += digits[num & 0xf];
    ans += digits[num >> 4];
  }

  return ans;
}

int destroy_enclave(sgx_enclave_id_t* const id) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  if ((ret = sgx_destroy_enclave(*id)) != SGX_SUCCESS) {
    return -1;
  }
  return 0;
}

void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  }
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

void store_idx_val(std::string uT, std::string eT, std::string uV, std::string eV, int ind, std::string enc){
  MYSQL mysql;

  char *server = "localhost";
  char *user = "user";
  char *password = "password";
  char *database = "luna";

  if (NULL == mysql_init(&mysql))
  {
    LOG(plog::info) << "mysql init error!";
  }

  if (!mysql_real_connect(&mysql, server, user, password, database, 0, NULL, 0))
  {
    LOG(plog::error) << "MYSQL error:" << mysql_error(&mysql);
  }
  mysql_set_character_set(&mysql, "utf8");
  char *sql_T = new char[1024];
  memset(sql_T, 0, 1024);
  sprintf(sql_T, "insert into tableT values(\"%s\", \"%s\")", 
                uT.c_str(),
                eT.c_str());
  if (mysql_query(&mysql, sql_T) != 0)
  {
    LOG(plog::error) << "SQL error:" << mysql_error(&mysql);
  }

  char *sql_V = new char[1024];
  memset(sql_V, 0, 1024);
  sprintf(sql_V, "insert into tableV values(\"%s\", \"%s\")", 
                uV.c_str(),
                eV.c_str());
  if (mysql_query(&mysql, sql_V) != 0)
  {
    LOG(plog::error) << "SQL error:" << mysql_error(&mysql);
  }

  char *sql = new char[1024];
  memset(sql, 0, 1024);
  sprintf(sql, "insert into tableenc values(%d, \"%s\")", 
                ind,
                enc.c_str());
  if (mysql_query(&mysql, sql) != 0)
  {
    LOG(plog::error) << "SQL error:" << mysql_error(&mysql);
  }
  mysql_close(&mysql);

  delete[] sql;
  delete[] sql_T;
  delete[] sql_V;
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
  MYSQL mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  char *server = "localhost";
  char *user = "user";
  char *password = "password";
  char *database = "luna";

  if (NULL == mysql_init(&mysql))
  {
    LOG(plog::info) << "mysql init error!";
  }

    
  if (!mysql_real_connect(&mysql, server, user, password, database, 0, NULL, 0))
  {
    LOG(plog::error) << "MYSQL connect error:" << mysql_error(&mysql);
  }
  mysql_set_character_set(&mysql, "utf8");
  std::string sign = "*";
  char *sql_V = new char[64];
  memset(sql_V, 0, 64);
  char *sub_eV = new char[48];
  for (auto it : vec_xV) {
    memset(sub_eV, 0, 48);
    sprintf(sql_V, "select eV from tableV where uV = \"%s\"", 
                it.c_str());
    if (mysql_query(&mysql, sql_V))
    {
        LOG(plog::info) << "MYSQL query error" << mysql_error(&mysql);
    }
    res = mysql_store_result(&mysql);
    row = mysql_fetch_row(res);
    if (row != NULL)
    {
        memcpy(sub_eV, row[0], strlen(row[0]));
    }
    else 
    {   
        LOG(plog::info) << "SQL query:" << sql_V;
        LOG(plog::info) << "Cannot get ev from mysql";
        return;
    }
    eV.append((std::string)sub_eV);
    eV.append(sign);
  }
  mysql_free_result(res);
  mysql_close(&mysql);
  delete[] sub_eV;
  delete[] sql_V;
}

void get_w_db(int num, std::string& ct) {
  MYSQL mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  char *server = "localhost";
  char *user = "user";
  char *password = "password";
  char *database = "luna";

  if (NULL == mysql_init(&mysql))
  {
    LOG(plog::info) << "mysql init error!";
  }

  if (!mysql_real_connect(&mysql, server, user, password, database, 0, NULL, 0))
  {
    LOG(plog::error) << "MYSQL connect error:" << mysql_error(&mysql);
  }
  mysql_set_character_set(&mysql, "utf8");
  std::string sign = "*";
  char *sql_enc = new char[64];
  memset(sql_enc, 0, 64);
  char *sub = new char[1024*1024*100];
  memset(sub, 0, 1024*1024*100);
  for(int i = 0; i < num; i++){
    sprintf(sql_enc, "select enc from tableenc where ind = %d", 
                  i);
    if (mysql_query(&mysql, sql_enc))
    {
      LOG(plog::info) << "MYSQL query error" << mysql_error(&mysql);
    }
    res = mysql_store_result(&mysql);
    row = mysql_fetch_row(res);
    if (row != NULL)
    {
      memcpy(sub, row[0], strlen(row[0]));
    }
    else 
    {   
      LOG(plog::info) << "Cannot get ev from mysql";
      return;
    }
    ct.append(sub);
  }
  mysql_free_result(res);
  mysql_close(&mysql);
  delete[] sub;
  delete[] sql_enc;
}

void delete_idx_val(std::string uT, std::string uV) {
  MYSQL mysql;

  char *server = "localhost";
  char *user = "user";
  char *password = "password";
  char *database = "luna";

  if (NULL == mysql_init(&mysql))
  {
    LOG(plog::info) << "mysql init error!";
  }

  if (!mysql_real_connect(&mysql, server, user, password, database, 0, NULL, 0))
  {
    LOG(plog::error) << "MYSQL error:" << mysql_error(&mysql);
  }

  mysql_set_character_set(&mysql, "utf8");
  char *d_sql_T = new char[1024];
  memset(d_sql_T, 0, 1024);
  sprintf(d_sql_T, "delete from tableT where uT = \"%s\"", 
                uT.c_str());
  if (mysql_query(&mysql, d_sql_T) != 0)
  {
    LOG(plog::error) << "SQL error:" << mysql_error(&mysql);
  }
  char *d_sql_V = new char[1024];
  memset(d_sql_V, 0, 1024);
  sprintf(d_sql_V, "delete from tableV where uV = \"%s\"", 
                uV.c_str());
  if (mysql_query(&mysql, d_sql_V) != 0)
  {
    LOG(plog::error) << "SQL error:" << mysql_error(&mysql);
  }
  mysql_close(&mysql);
  delete[] d_sql_T;
  delete[] d_sql_V;
}
void get_from_edb(std::string tab_name, std::string val_name, std::string key_name, char* xuT, std::string& xeT) {
  std::vector<std::string> vec_xT;
  std::string pattern = "*";
  char* tmpStr = strtok(xuT, pattern.c_str());
  while (tmpStr != NULL)
  {
    vec_xT.push_back(std::string(tmpStr));
    tmpStr = strtok(NULL, pattern.c_str());
  }
  MYSQL mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  char *server = "localhost";
  char *user = "user";
  char *password = "password";
  char *database = "luna";

  if (NULL == mysql_init(&mysql))
  {
    LOG(plog::info) << "mysql init error!";
  }

  if (!mysql_real_connect(&mysql, server, user, password, database, 0, NULL, 0))
  {
    LOG(plog::error) << "MYSQL connect error:" << mysql_error(&mysql);
  }
  mysql_set_character_set(&mysql, "utf8");
  std::string sign = "*";
  char *sql_T = new char[64];
  memset(sql_T, 0, 64);
  char *sub_eT = new char[48];
  for (auto it : vec_xT) {
    memset(sub_eT, 0, 48);
    sprintf(sql_T, "select %s from %s where %s = \"%s\"",
                val_name.c_str(),
                tab_name.c_str(), 
                key_name.c_str(),
                it.c_str());
    if (mysql_query(&mysql, sql_T))
    {
        LOG(plog::info) << "MYSQL query error" << mysql_error(&mysql);
    }
    res = mysql_store_result(&mysql);

    row = mysql_fetch_row(res);
    if (row != NULL)
    {
        memcpy(sub_eT, row[0], strlen(row[0]));
    }
    else 
    {   
        LOG(plog::info) << "SQL Query:" << sql_T;
        LOG(plog::info) << "Cannot get eT from mysql";
        return;
    }
    xeT.append((std::string)sub_eT);
    xeT.append(sign);
  }
  mysql_free_result(res);
  mysql_close(&mysql);
  delete[] sub_eT;
  delete[] sql_T;
}
}  // namespace sgx_sse

#pragma once

#include <unistd.h>
#include <pwd.h>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
//#include <ifstream>
#include <iostream>
#include <sstream>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "ErrorSupport.h"
#include "mysql.h"
#include "my_alloc.h"
#include "oneitem.h"
#include "App.h"

using namespace std;


char ai[100] = {0};
extern "C"
{
    

    long long init_sse(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err);
    my_bool init_sse_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void init_sse_deinit(UDF_INIT* initid);

    char* add_record(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool add_record_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void add_record_deinit(UDF_INIT* initid);

    void delete_record(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);
    my_bool delete_record_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void delete_record_deinit(UDF_INIT* initid);

    char* search_w(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool search_w_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void search_w_deinit(UDF_INIT* initid);

    void finish_sse(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err);
    my_bool finish_sse_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void finish_sse_deinit(UDF_INIT* initid);
}


int init_enclave(sgx_enclave_id_t* const id) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_launch_token_t launch_token = {0};
  int updated = 0;

  ret = sgx_create_enclave(enclave_path.c_str(), 1, &launch_token, &updated, id, nullptr);
  if (ret != SGX_SUCCESS) {
    return -1;
  }
  return 0;
}

sgx_status_t read_and_unseal_state(sgx_enclave_id_t* const global_eid, std::string filename, bool flag) {
  sgx_status_t ret;
    
  size_t fsize = get_file_size((char *)filename.c_str());
  if (fsize == (size_t)-1)
  {
    return SGX_ERROR_UNEXPECTED;
  }
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if(temp_buf == NULL)
  {
    return SGX_ERROR_UNEXPECTED;
  }
  if (read_file_to_buf((char *)filename.c_str(), temp_buf, fsize) == false)
  {
    free(temp_buf);
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t retval;
  if (flag) {
    ret = unseal_state(*global_eid, &retval, temp_buf, fsize);
  } else {
    ret = unseal_delset(*global_eid, &retval, temp_buf, fsize);
  }
  
  if (ret != SGX_SUCCESS)
  {
    free(temp_buf);
    return SGX_ERROR_UNEXPECTED;
  }
  else if(retval != SGX_SUCCESS)
  {
    free(temp_buf);
    return SGX_ERROR_UNEXPECTED;
  }

  free(temp_buf);
  return SGX_SUCCESS;
}

sgx_status_t seal_and_save_state(sgx_enclave_id_t* const global_eid, std::string filename, bool flag) {
  sgx_status_t ret;
  uint32_t sealed_data_size = 0;
  if (flag) {
    ret = get_sealed_state_size(*global_eid, &sealed_data_size);
  } else{
    ret = get_sealed_delset_size(*global_eid, &sealed_data_size);
  }
  
  if (ret != SGX_SUCCESS)
  {
    return ret;
  }
  else if(sealed_data_size == UINT32_MAX)
  {
    return ret;
  }
    
  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  if(temp_sealed_buf == NULL)
  {
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t retval;

  if(flag){
    ret = seal_state(*global_eid, &retval, temp_sealed_buf, sealed_data_size);
  } else {
    ret = seal_delset(*global_eid, &retval, temp_sealed_buf, sealed_data_size);
  }

  if (ret != SGX_SUCCESS)
  {
    free(temp_sealed_buf);
    return ret;
  }
  else if( retval != SGX_SUCCESS)
  {
    free(temp_sealed_buf);
    return ret;
  }

  if (write_buf_to_file((char *)filename.c_str(), temp_sealed_buf, sealed_data_size, 0) == false)
  {
    free(temp_sealed_buf);
    return SGX_ERROR_UNEXPECTED;
  }

  free(temp_sealed_buf);
  return SGX_SUCCESS;
}


my_bool init_sse_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}
long long init_sse(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err){
    if (init_enclave(global_eid)){
        if (read_and_unseal_state(global_eid, statefile, 1)!= SGX_SUCCESS){
            return 0;
        } else {
            return 1;
        }
        if (read_and_unseal_state(global_eid, delfile, 0)!= SGX_SUCCESS){
            return 0;
        } else {
            return 1;
        }
    } else {
        return 0;
    }
}

void init_sse_deinit(UDF_INIT* initid){
    return;
}


my_bool add_record_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}

char* add_record(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)//udf
{
    int ind = 1;
    std::string w = "record1";
    std::string secret = w;
    std::string sign = "*";
    secret.append(sign);
    secret.append(std::to_string(ind));
    secret.append(sign);

    int aw = 0;
    std::unordered_map<std::string, state>::iterator it = client_st.find(w);
    if (it == client_st.end()) {
        state initSt(0,0);
        client_st.insert(std::make_pair(w, initSt)); 
    } else {
        aw = (it->second).aw;
    }
    secret.append(std::to_string(aw));
    secret.append(sign);
    std::string kV = tkV;
    std::string ivV = tivV;
    get_kv_ivv(kV, ivV, secret);

    std::string enc_enc_secret;
    gen_enc_secret(secret, enc_enc_secret);


    std::string h1, h2;
    std::string eT;
    unsigned char* ckT = new unsigned char[17];
    memset(ckT, 0, 17);
    memcpy(ckT, tkT, 16);
    unsigned char* civT = new unsigned char[17];
    memset(civT, 0, 17);
    memcpy(civT, tivT, 16);
    std::string kw = Genkw(ckT, civT, w);
    GenuT(kw, aw, h1, h2);
 
    GeneT(ind, h2, eT);

    ClientSt_update(w, client_st, true);

    clientst_show(client_st);

    char *m_ivec = new char[17];
    memset(m_ivec, 0, 17);
    randstr(m_ivec, 16);
    std::string enc = EncryptionAES(m_userKey, (unsigned char*)m_ivec, w);
    std::string siv = m_ivec;
    enc.append(siv);

    
    std::string uT = h1;
    std::string cst = enc_enc_secret;

    sgx_status_t ret, retval;

    char *cuV = new char[48];
    char *ceV = new char[48];
    
    ret = ecall_add_gen_V(*global_eid, &retval, 
                    (char *)cst.c_str(), 
                    cst.length(), 
                    cuV, 
                    48, 
                    ceV, 
                    48);
  
    if (ret != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    } else if (retval != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    std::string uV = cuV;
    std::string eV = ceV;
    
  
    store_idx_val(uT, eT, uV, eV);
    

    
    delete[] cuV;
    delete[] ceV;                   
    delete[] m_ivec;
  
    
    
    *length = (unsigned long)strlen((enc.c_str()));
    memcpy(result, enc.c_str(), *length);
    
    return result;
}

void add_record_deinit(UDF_INIT* initid){
    return;
}

my_bool delete_record_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}
void delete_record(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    int aw = 0;
    int nw = 0;  
    int ind = 1;
    std::string w = "record1";
    std::string sign = "*";
    std::unordered_map<std::string, state>::iterator it = client_st.find(w);
    if (it == client_st.end()) { 
        return;
    } else {
        aw = (it->second).aw;
        nw = (it->second).nw;
    }
    std::string secret;
    secret = w;
    secret.append(sign);
    secret.append(std::to_string(ind));
    secret.append(sign);

    std::string kT = tkT;
    std::string ivT = tivT;
    std::string kV = tkV;
    std::string ivV = tivV;
    get_k_iv(kT, ivT, kV, ivV, secret);

    std::string enc_enc_secret;
    gen_enc_secret(secret, enc_enc_secret);

    ClientSt_update(w, client_st, false);

    

    std::string cst = enc_enc_secret;
    int ind = 1;
    sgx_status_t ret, retval;
    char *xV = new char[1024*1024*100];
  
    ret = ecall_del_gen_V(*global_eid, &retval, 
                    (char *)cst.c_str(), 
                    cst.length(), 
                    xV, 
                    1024*1024*100);
    if (ret != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    } else if (retval != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
    std::string eV;
  
    get_eV((std::string)xV, eV);
    
    char* uT = new char[64];
    char* uV = new char[64];
    ret = ecall_update_D(*global_eid, &retval, 
                      (char *)cst.c_str(),
                      cst.length(), 
                      (char*)eV.c_str(), 
                      eV.length(),
                      uT,
                      64,
                      uV,
                      64);
    if (ret != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    } else if (retval != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
  
    delete_idx_val(uT, uV);
  

    delete[] xV;
    delete[] uT;
    delete[] uV;
}

void delete_record_deinit(UDF_INIT* initid){
    return;
}

my_bool search_w_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    return 0;
}


char* search(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error){
    std::string sign = "*";
    std::string secret = "record1";
    secret.append(sign);

    std::unordered_map<std::string, state>::iterator it = client_st.find(w);
    if (it == client_st.end()) { 
        return -1;
    } 
    int nw = (it->second).nw;
    char *cnw = new char[10];
    memset(cnw, 0, 10);
    memcpy(cnw, std::to_string(nw).c_str(), std::to_string(nw).length());
    std::string snw = cnw;
    secret.append(snw);
    secret.append(sign);

    unsigned char* ckT = new unsigned char[17];
    memset(ckT, 0, 17);
    memcpy(ckT, tkT, 16);
    unsigned char* civT = new unsigned char[17];
    memset(civT, 0, 17);
    memcpy(civT, tivT, 16);
    std::string kw = Genkw(ckT, civT, w);

    secret.append(kw);
    secret.append(sign);
    std::string enc_enc_secret;
    gen_enc_secret(secret, enc_enc_secret);

    std::string cst = enc_enc_secret;
    sgx_status_t ret, retval;
    char *xuT = new char[1024*1024*100];
    char *xNum = new char[1024*1024*100];

    ret = ecall_search_w(*global_eid, &retval, 
                      (char *)cst.c_str(),
                      cst.length(),
                      xuT,
                      1024*1024*100,
                      xNum,
                      1024*1024*100);
    if (ret != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    } else if (retval != SGX_SUCCESS) {
        return SGX_ERROR_UNEXPECTED;
    }
  

    std::string xeT;
  
    get_from_edb("tableT", xuT, xeT);
  

    char *xind = new char[1024*1024*100];
    ret = ecall_get_res(*global_eid, &retval,
                      (char *)cst.c_str(),
                      cst.length(),
                      (char*)xeT.c_str(),
                      xeT.length(),
                      xNum, 
                      strlen(xNum),
                      xind,
                      1024*1024*100);

    delete[] xuT;
    delete[] xNum;
    delete[] xind;
    delete[] cnw;
    delete[] ckT;
    delete[] civT;

    *length = (unsigned long)strlen(xind);
    memcpy(result, xind, *length);
    
    return result;
}

void search_w_deinit(UDF_INIT* initid){
    return;
}

my_bool finish_sse_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    return 0;
}

void finish_sse_deinit(UDF_INIT* initid) {
    return;
}

void finish_sse(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err) {
    if (seal_and_save_state(global_eid, statefile, 1) != SGX_SUCCESS) {
        return;
    }
    if (seal_and_save_state(global_eid, delfile, 0) != SGX_SUCCESS) {
        return;
    }
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if ((ret = sgx_destroy_enclave(global_eid)) != SGX_SUCCESS) {
        return;
    }
  return;
}
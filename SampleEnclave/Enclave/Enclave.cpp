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
#pragma once
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdint.h>
#include "hash.h"
#include "Base64.h"
#include <algorithm>
#include "util.h"
using namespace std;


struct Is {
    std::string ind;
    int number;
};
Is *aaa = new Is[100];
int ilen = 0;

std::string Istr;
std::string Dstr;
std::shared_ptr<EnclaveCryptoManager> sse_crypto_manager = EnclaveCryptoManager::get_instance();
std::unordered_map<std::string, int> I;
std::unordered_map<std::string, int> D;

uint32_t get_sealed_state_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(Istr.c_str()));         
}
uint32_t get_sealed_delset_size() 
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(Dstr.c_str()));
}
sgx_status_t seal_state(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(Istr.c_str()));
    
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err = sgx_seal_data((uint32_t)strlen(aad_mac_text), 
                                    (const uint8_t *)aad_mac_text, 
                                    (uint32_t) strlen((const char*)aaa),
                                    (const unsigned char*)aaa, 
                                    sealed_data_size, 
                                    (sgx_sealed_data_t *)temp_sealed_buf);
   
    
    if (err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t seal_delset(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(Dstr.c_str()));

    
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err = sgx_seal_data((uint32_t)strlen(aad_mac_text), 
                                    (const uint8_t *)aad_mac_text, 
                                    (uint32_t)strlen(Dstr.c_str()), 
                                    (uint8_t *)Dstr.c_str(), 
                                    sealed_data_size, 
                                    (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t unseal_state(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, 
                                        de_mac_text, 
                                        &mac_text_len, 
                                        decrypt_data, 
                                        &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    memcpy((char*)&aaa, decrypt_data, ilen * sizeof(Is));
    
    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

sgx_status_t unseal_delset(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, 
                                        de_mac_text, 
                                        &mac_text_len, 
                                        decrypt_data, 
                                        &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    char *str = new char[decrypt_data_len + 1];
    memset(str, 0, decrypt_data_len + 1);
    memcpy(str, decrypt_data, decrypt_data_len);
    Dstr = str;
    
    
    free(de_mac_text);
    free(decrypt_data);
    delete[] str;
    return ret;
}
sgx_status_t ecall_add_gen_V(char *enc_st, int data_size, char *cuV, int uVlen, char *ceV, int eVlen){
    if (data_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    Is item;
    for (int i = 0; i < ilen ; i++) {
        item = aaa[i];
    }
    std::string cst;
    Decrypt(sse_crypto_manager, enc_st, data_size, cst);
    std::string w, ind, aw, kV, ivV;
    parse_add_state(cst, w, ind, aw, kV, ivV);
    
    char *cind = new char[10];
    memset(cind, 0, 10);
    memcpy(cind, ind.c_str(), ind.length());
    ind = cind;
    
    std::string kind = sse_crypto_manager->aes_encrypt((unsigned char*)kV.c_str(), (unsigned char*)ivV.c_str(), ind);//生成kind
    std::string kind_base64 = base64_encode((const unsigned char*)kind.c_str(), kind.length());
    
    
    int cnt = 0;
    int j = 0;
    
    for (j = 0 ; j < ilen; j ++) {
        if (ind.compare(item.ind) == 0) {
            item = aaa[j];
            cnt = item.number;
            item.number = cnt + 1;
        } 
    }
    if (cnt == 0) {
        ilen ++;
        item = aaa[j];
        item.ind = ind;
        item.number = 1;
    }
    

    
    std::string uV, h2, eV;
    GenuV(std::to_string(cnt), kind, uV, h2);
    
    GeneV(w, aw, h2, eV);
    
    memset(cuV, 0, uVlen);
    memcpy(cuV, uV.c_str(), uV.length());
    memset(ceV, 0, eVlen);
    memcpy(ceV, eV.c_str(), eV.length());

    
    delete[] cind;
    return SGX_SUCCESS;
}

sgx_status_t ecall_del_gen_V(char *enc_st, int data_size, char *xV, int xVlen) {
    if (data_size == 0){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    str_to_Map(Istr, I);
    
    std::string cst;
    Decrypt(sse_crypto_manager, enc_st, data_size, cst);

    std::string w, ind, kT, ivT, kV, ivV;
    parse_del_state(cst, w, ind, kT, ivT, kV, ivV);
    

    std::unordered_map<std::string, int>::iterator it = I.find(ind);
    if (it == I.end()){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    int cnt = it->second;

    char *cind = new char[10];
    memset(cind, 0, 10);
    memcpy(cind, ind.c_str(), ind.length());
    ind = cind;
    std::string kind = sse_crypto_manager->aes_encrypt((unsigned char*)kV.c_str(), (unsigned char*)ivV.c_str(), ind);//生成kind
    

    std::string uV, h2, sxV;
    std::string sign = "*";
    for (int i = 0; i < cnt; i ++) {
        GenuV(std::to_string(i), kind, uV, h2);
        sxV.append(uV);
        sxV.append(sign);
    }
    memset(xV, 0, xVlen);
    memcpy(xV, sxV.c_str(), sxV.length());
    delete[] cind;
    return SGX_SUCCESS;
}

sgx_status_t ecall_update_D(char *enc_st, 
                            int data_size, 
                            char *eV, 
                            int eVlen, 
                            char*uT, 
                            int uTlen, 
                            char*uV, 
                            int uVlen) {
    if (eVlen == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    str_to_Map(Istr, I);

    std::string cst;
    Decrypt(sse_crypto_manager, enc_st, data_size, cst);

    std::string w, ind, kT, ivT, kV, ivV;
    std::string sign = "*";
    parse_del_state(cst, w, ind, kT, ivT, kV, ivV);

    std::unordered_map<std::string, int>::iterator it = I.find(ind);
    if (it == I.end()){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    int cnt = it->second;

    std::vector<std::string> vec_eV, vec_h4;
    parse_eV(eV, vec_eV);
    std::string kind = sse_crypto_manager->aes_encrypt((unsigned char*)kV.c_str(), (unsigned char*)ivV.c_str(), ind);//生成kind
    gen_h4(kind, cnt, vec_h4);
    
    char* res = new char[17];
    memset(res, 0, 17);
    std::string dind;
    int j;
    char *ceV = new char[17];
    char *ch4 = new char[17];
    for(j = 0 ; j < cnt; j++){
        memset(ceV, 0, 17);
        memcpy(ceV, vec_eV[j].c_str(), vec_eV[j].length());
        std::string ss = base64_encode((const unsigned char*)vec_eV[j].c_str(), 16);
        
        memset(ch4, 0, 17);
        memcpy(ch4, vec_h4[j].c_str(), vec_h4[j].length()); 
        ss = base64_encode((const unsigned char*)vec_h4[j].c_str(), 16);
        for(int i = 0; i < 16; i++) {
            res[i] = ceV[i] ^ ch4[i];
        }
        std::string sres = res;
        std::string dot = ",";
        std::string emp = "@";
        if (sres.find(w) != std::string::npos) {
            int h = sres.find(dot);
            int k = sres.find(emp);
            std::string ww = sres.substr(0, h + 1);
            Dstr.append(ww);
            dind = sres.substr(h + 1, k - h - 1);
            Dstr.append(dind);
            Dstr.append(sign);
            break;
        }
    }

    std::string kw = sse_crypto_manager->aes_encrypt((unsigned char*)kT.c_str(), (unsigned char*)ivT.c_str(), w);
    
    std::string suT;
    GenuT(kw, dind, suT);
    memset(uT, 0, uTlen);
    memcpy(uT, suT.c_str(), suT.length());

    std::string suV, h2;
    GenuV(std::to_string(j), kind, suV, h2);
    
    memset(uV, 0, uVlen);
    memcpy(uV, suV.c_str(), suV.length());


    delete[] res;
    delete[] ceV;
    delete[] ch4;

    return SGX_SUCCESS;
}

sgx_status_t ecall_search_w(char *enc_st, int data_size, char *xuT, int len, char *xNum, int lenNum) {
    if (data_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    str_to_Map(Dstr, D);//Load(D)
    
    std::string cst;
    Decrypt(sse_crypto_manager, enc_st, data_size, cst);

    std::string w, nw, kw;
    parse_search_state(cst, w, nw, kw);

    int inw = atoi((char*)nw.c_str());
    int *Num = new int[inw];
    for (int i = 0; i < inw; i++) {
        Num[i] = i;
    }
    bool cond, cond1, cond2;
    for (auto &it : D) {
        cond1 = w.compare(it.first);
        for (int i = 0; i < inw; i++) {
            cond2 = (i < it.second);
            cond = cond1 || cond2;
            Num[i] += int(!cond);
        }
    }

    std::string uT,sxuT;
    std::string sign = "*";
    for(int i = 0 ; i < inw; i++) {
        GenuT(kw, std::to_string(Num[i]), uT);
        sxuT.append(uT);
        sxuT.append(sign);
    }
    memset(xuT, 0, 1024*1024*100);
    memcpy(xuT, sxuT.c_str(), sxuT.length());
    
    memset(xNum, 0, 1024*1024*100);
    
    std::string tmp,tmp_enc;
    std::string iv;
    char *ctmp = new char[2*inw + 1];
    memset(ctmp, 0, 2*inw + 1);
    for (int i = 0 ; i < inw; i++) {
        ctmp[2*i] = Num[i] + '0';
        ctmp[2*i+1] = '*';
    }
    tmp = ctmp;

    tmp_enc = sse_crypto_manager->enclave_aes_128_gcm_encrypt(tmp);
    
    memcpy(xNum, tmp_enc.c_str(), tmp_enc.length());

    delete[] Num;
    delete[] ctmp;

    return SGX_SUCCESS;
}

sgx_status_t ecall_get_res(char *enc_st, int data_size, char* xeT, int xeTsize, char* xNum, int numlen, char* xind, int indlen) {
    if (data_size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (xeTsize == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    std::string cst;
    Decrypt(sse_crypto_manager, enc_st, data_size, cst);

    std::string w, nw, kw;
    parse_search_state(cst, w, nw, kw);
    
    char* cNum = new char[1024*1024*100];
    memset(cNum, 0, 1024*1024*100);
    memcpy(cNum, xNum, numlen);

    std::string tmp = cNum;
    std::string sNum = sse_crypto_manager->enclave_aes_128_gcm_decrypt(tmp);

    std::vector<std::string> veT;
    str_to_Vec(xeT, veT);
    for (auto &it:veT) {
        it = base64_decode(it);
    }

    int inw = atoi((char*)nw.c_str());
    int *Num = new int[inw];
    parse_Num(sNum, Num, inw);

    std::string h2, sind, sxind;
    char *cind = new char[17];
    int j;
    std::string sign = "*";
    for (int i = 0; i < inw; i++) {
        memset(cind, 0, 16);
        gen_h2(kw, Num[i], h2);
        for (int j = 0; j < 16; j++) {
            cind[j] = h2.c_str()[j] ^ veT[i].c_str()[j];
        }
        sind = cind;
        j = sind.find(sign);

        sxind.append(sind.substr(0, j + 1));
    }
    memset(xind, 0, 1024*1024*100);
    memcpy(xind, sxind.c_str(), sxind.length());

    delete[] cNum;
    delete[] Num;
    delete[] cind;
    
    return SGX_SUCCESS;
}
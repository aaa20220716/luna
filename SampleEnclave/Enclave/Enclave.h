/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_
#pragma once
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <iostream>
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "sgx_urts.h"

using namespace std;

struct myaeskey{
    char* skey;
    char* iv;
};

class mystate {
public:
    char *keyword;
    int cnt;
    int del;
public:
    mystate(){
        this->keyword = new char[100];
        this->cnt = 0;
        this->del = 0;
    }
    ~mystate(){
        if(!this->keyword) {
            delete this->keyword;
        }
    }
    char* getKeyWord(){
        return this->keyword;
    }
    void setKeyWord(string dest, int length){
        strncpy(this->keyword, dest.c_str(), length);
        this->keyword[length] = '\0';
    }
    void setCnt(int cnt){
        this->cnt = cnt;
    }
    void setDel(int del){
        this->del = del;
    }
};


#if defined(__cplusplus)
extern "C" {
#endif

char* printf(const char *fmt, ...);
void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen);
sgx_status_t parsestate(char *keyword, mystate &myst);
void uptst(mystate &myst);
void cntInc(mystate &myst);
void delInc(mystate &myst);
int genLabelw(string keyw, char *kw, char *labelw);
int genkeywdel(char *keyword, string& keyw, string& keyDel);
int genH4(string strdel, char *labeldel, string keyDel);
sgx_status_t parsedellist(char *blockDel);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */

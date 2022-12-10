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

#pragma once
#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/time.h>
#include "oneitem.h"
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif


# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "/usr/lib/enclave.signed.so"

extern sgx_enclave_id_t eid;    /* global enclave id */
static const std::string key_path = "../key";

static const std::string enclave_path = "../enclave_signed.so";
static sgx_enclave_id_t global_eid = 0;
std::string statefile="statefile.txt";
std::unordered_map<std::string, state> client_st;
std::string delfile = "delfile.txt";


unsigned char m_userKey [16];
  //unsigned char m_ivec [16];  // Default value is all 0 of 16

unsigned char tkT [16];
unsigned char tivT [16];

unsigned char tkV [16];
unsigned char tivV [16];

memcpy(m_userKey, "XZJE151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4FTP", 16);
  //memcpy(m_ivec, "XZJ2030405060708090A0B0C0D0E0FTP", IVEC_LENGTH);  // Vector initialization

memcpy(kT, "shfnekwiahdteghfkapwur63894nbx73h395jh583h367fh3", 16);
memcpy(ivT, "936cfbeiw64ghfjqwy2f3tdg4u5784h3h2jdjqvjewk2382365", 16);

memcpy(kV, "tgwikoewjhwbiqwhsd632901hx5374652hdbr", 16);
memcpy(ivV, "h236754912hydsxbri32fg125weu854hdf723y438", 16);

#if defined(__cplusplus)
extern "C" {
#endif
    

    


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */

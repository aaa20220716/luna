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

#include <sgx_urts.h>

#include <plog/Record.h>
#include <sys/time.h>
#include <string>
#include <vector>
#include <fstream>
#include <mysql.h>
#include "enclave/enclave_u.h"

#include "ErrorSupport.h"

static const std::string digits = "0123456789abcdef";
#define SEALED_DATA_FILE "sealed_data_blob.txt"

extern "C" {
void ocall_printf(const char* fmt);
}

// This file contains wrapper functions and some utility functions
// for the untrusted application and the enclave.
namespace sgx_sse {
static const std::string candidate =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

std::vector<std::string> generate_random_strings(const uint32_t& number,
                                                 const uint32_t& length = 32);
std::vector<std::string> get_data_from_file(std::ifstream* const file);
uint32_t ecall_uniform_random(sgx_enclave_id_t* const id, const uint32_t& lower,
                              const uint32_t& upper);
uint32_t untrusted_uniform_random(const uint32_t& lower, const uint32_t& upper);
void print_error_message(sgx_status_t ret);
int init_enclave(sgx_enclave_id_t* const id);
size_t get_file_size(char *filename);
bool read_file_to_buf(char *filename, uint8_t *buf, size_t bsize);
bool write_buf_to_file(char *filename, const uint8_t *buf, size_t bsize, long offset);
int destroy_enclave(sgx_enclave_id_t* const id);
std::string hex_to_string(const uint8_t* array, const size_t& len = 32);
void safe_free(void* ptr);
void get_w_db(int num, std::string& ct);
void store_idx_val(std::string uT, std::string eT, std::string uV, std::string ev, int ind, std::string enc);
void delete_idx_val(std::string uT, std::string uV);
void get_eV(std::string xV, std::string& eV);
void get_from_edb(std::string tab_name, std::string val_name, std::string key_name, char* xuT, std::string& xeT);
}  // namespace sgx_sse
#endif
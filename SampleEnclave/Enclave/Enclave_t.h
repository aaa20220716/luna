#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_test(size_t in, size_t* out);
uint32_t get_sealed_data_size(char* encrypt_data);
sgx_status_t seal_data(uint8_t* sealed_blob, uint32_t data_size, char* encrypt_data);
uint32_t get_sealed_state_size(void);
uint32_t get_sealed_dellist_size(void);
sgx_status_t seal_state(uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t seal_DList(uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t unseal_state(const uint8_t* sealed_blob, size_t data_size);
sgx_status_t unseal_dellist(const uint8_t* sealed_blob, size_t data_size);
sgx_status_t parsekey(void);
sgx_status_t insertidx(char* keyword, int keysize, int id, char* BlockInd, int lengthInd, char* BlockW, int lengthW);
sgx_status_t genLabelInd(char* ind, int lencind, char* labelInd, int lenlabelInd);
sgx_status_t genlabelw(char* labelwStar, int lenStar, char* ind, int lencind, char* labelw, int lenw, char* BlockDel, int lenbdel, char* wdellabel, int wdellen);
sgx_status_t genLabeldel(char* keyword, int lenword, char* strdel, int lendel);
sgx_status_t GetLabelRes(char* keyword, int lenword, char* labelSetOut, int lenOut, char* labelRes, int lenlres);
sgx_status_t getInd(char* keyword, int lenword, char* res, int len, char* ids, int idlen);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_insertidx_err(char* err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

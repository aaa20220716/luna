#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_INSERTIDX_ERR_DEFINED__
#define OCALL_INSERTIDX_ERR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_insertidx_err, (char* err));
#endif

sgx_status_t ecall_test(sgx_enclave_id_t eid, size_t in, size_t* out);
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, char* encrypt_data);
sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size, char* encrypt_data);
sgx_status_t get_sealed_state_size(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t get_sealed_dellist_size(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t seal_state(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t seal_DList(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size);
sgx_status_t unseal_state(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size);
sgx_status_t unseal_dellist(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size);
sgx_status_t parsekey(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t insertidx(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int keysize, int id, char* BlockInd, int lengthInd, char* BlockW, int lengthW);
sgx_status_t genLabelInd(sgx_enclave_id_t eid, sgx_status_t* retval, char* ind, int lencind, char* labelInd, int lenlabelInd);
sgx_status_t genlabelw(sgx_enclave_id_t eid, sgx_status_t* retval, char* labelwStar, int lenStar, char* ind, int lencind, char* labelw, int lenw, char* BlockDel, int lenbdel, char* wdellabel, int wdellen);
sgx_status_t genLabeldel(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* strdel, int lendel);
sgx_status_t GetLabelRes(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* labelSetOut, int lenOut, char* labelRes, int lenlres);
sgx_status_t getInd(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* res, int len, char* ids, int idlen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_test_t {
	size_t ms_in;
	size_t* ms_out;
} ms_ecall_test_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	char* ms_encrypt_data;
	size_t ms_encrypt_data_len;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
	char* ms_encrypt_data;
	size_t ms_encrypt_data_len;
} ms_seal_data_t;

typedef struct ms_get_sealed_state_size_t {
	uint32_t ms_retval;
} ms_get_sealed_state_size_t;

typedef struct ms_get_sealed_dellist_size_t {
	uint32_t ms_retval;
} ms_get_sealed_dellist_size_t;

typedef struct ms_seal_state_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_seal_state_t;

typedef struct ms_seal_DList_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_seal_DList_t;

typedef struct ms_unseal_state_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
} ms_unseal_state_t;

typedef struct ms_unseal_dellist_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
} ms_unseal_dellist_t;

typedef struct ms_parsekey_t {
	sgx_status_t ms_retval;
} ms_parsekey_t;

typedef struct ms_insertidx_t {
	sgx_status_t ms_retval;
	char* ms_keyword;
	int ms_keysize;
	int ms_id;
	char* ms_BlockInd;
	int ms_lengthInd;
	char* ms_BlockW;
	int ms_lengthW;
} ms_insertidx_t;

typedef struct ms_genLabelInd_t {
	sgx_status_t ms_retval;
	char* ms_ind;
	int ms_lencind;
	char* ms_labelInd;
	int ms_lenlabelInd;
} ms_genLabelInd_t;

typedef struct ms_genlabelw_t {
	sgx_status_t ms_retval;
	char* ms_labelwStar;
	int ms_lenStar;
	char* ms_ind;
	int ms_lencind;
	char* ms_labelw;
	int ms_lenw;
	char* ms_BlockDel;
	int ms_lenbdel;
	char* ms_wdellabel;
	int ms_wdellen;
} ms_genlabelw_t;

typedef struct ms_genLabeldel_t {
	sgx_status_t ms_retval;
	char* ms_keyword;
	int ms_lenword;
	char* ms_strdel;
	int ms_lendel;
} ms_genLabeldel_t;

typedef struct ms_GetLabelRes_t {
	sgx_status_t ms_retval;
	char* ms_keyword;
	int ms_lenword;
	char* ms_labelSetOut;
	int ms_lenOut;
	char* ms_labelRes;
	int ms_lenlres;
} ms_GetLabelRes_t;

typedef struct ms_getInd_t {
	sgx_status_t ms_retval;
	char* ms_keyword;
	int ms_lenword;
	char* ms_res;
	int ms_len;
	char* ms_ids;
	int ms_idlen;
} ms_getInd_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_insertidx_err_t {
	char* ms_err;
} ms_ocall_insertidx_err_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_insertidx_err(void* pms)
{
	ms_ocall_insertidx_err_t* ms = SGX_CAST(ms_ocall_insertidx_err_t*, pms);
	ocall_insertidx_err(ms->ms_err);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_insertidx_err,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid, size_t in, size_t* out)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_in = in;
	ms.ms_out = out;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, char* encrypt_data)
{
	sgx_status_t status;
	ms_get_sealed_data_size_t ms;
	ms.ms_encrypt_data = encrypt_data;
	ms.ms_encrypt_data_len = encrypt_data ? strlen(encrypt_data) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size, char* encrypt_data)
{
	sgx_status_t status;
	ms_seal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_encrypt_data = encrypt_data;
	ms.ms_encrypt_data_len = encrypt_data ? strlen(encrypt_data) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_state_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_get_sealed_state_size_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_sealed_dellist_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_get_sealed_dellist_size_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_state(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_seal_state_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_DList(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_blob, uint32_t data_size)
{
	sgx_status_t status;
	ms_seal_DList_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_state(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size)
{
	sgx_status_t status;
	ms_unseal_state_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_dellist(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size)
{
	sgx_status_t status;
	ms_unseal_dellist_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t parsekey(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_parsekey_t ms;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t insertidx(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int keysize, int id, char* BlockInd, int lengthInd, char* BlockW, int lengthW)
{
	sgx_status_t status;
	ms_insertidx_t ms;
	ms.ms_keyword = keyword;
	ms.ms_keysize = keysize;
	ms.ms_id = id;
	ms.ms_BlockInd = BlockInd;
	ms.ms_lengthInd = lengthInd;
	ms.ms_BlockW = BlockW;
	ms.ms_lengthW = lengthW;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t genLabelInd(sgx_enclave_id_t eid, sgx_status_t* retval, char* ind, int lencind, char* labelInd, int lenlabelInd)
{
	sgx_status_t status;
	ms_genLabelInd_t ms;
	ms.ms_ind = ind;
	ms.ms_lencind = lencind;
	ms.ms_labelInd = labelInd;
	ms.ms_lenlabelInd = lenlabelInd;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t genlabelw(sgx_enclave_id_t eid, sgx_status_t* retval, char* labelwStar, int lenStar, char* ind, int lencind, char* labelw, int lenw, char* BlockDel, int lenbdel, char* wdellabel, int wdellen)
{
	sgx_status_t status;
	ms_genlabelw_t ms;
	ms.ms_labelwStar = labelwStar;
	ms.ms_lenStar = lenStar;
	ms.ms_ind = ind;
	ms.ms_lencind = lencind;
	ms.ms_labelw = labelw;
	ms.ms_lenw = lenw;
	ms.ms_BlockDel = BlockDel;
	ms.ms_lenbdel = lenbdel;
	ms.ms_wdellabel = wdellabel;
	ms.ms_wdellen = wdellen;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t genLabeldel(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* strdel, int lendel)
{
	sgx_status_t status;
	ms_genLabeldel_t ms;
	ms.ms_keyword = keyword;
	ms.ms_lenword = lenword;
	ms.ms_strdel = strdel;
	ms.ms_lendel = lendel;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t GetLabelRes(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* labelSetOut, int lenOut, char* labelRes, int lenlres)
{
	sgx_status_t status;
	ms_GetLabelRes_t ms;
	ms.ms_keyword = keyword;
	ms.ms_lenword = lenword;
	ms.ms_labelSetOut = labelSetOut;
	ms.ms_lenOut = lenOut;
	ms.ms_labelRes = labelRes;
	ms.ms_lenlres = lenlres;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t getInd(sgx_enclave_id_t eid, sgx_status_t* retval, char* keyword, int lenword, char* res, int len, char* ids, int idlen)
{
	sgx_status_t status;
	ms_getInd_t ms;
	ms.ms_keyword = keyword;
	ms.ms_lenword = lenword;
	ms.ms_res = res;
	ms.ms_len = len;
	ms.ms_ids = ids;
	ms.ms_idlen = idlen;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}


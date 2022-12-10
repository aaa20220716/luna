#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_test_t* ms = SGX_CAST(ms_ecall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_out = ms->ms_out;
	size_t _len_out = sizeof(size_t);
	size_t* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (size_t*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ecall_test(ms->ms_in, _in_out);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_data_size_t* ms = SGX_CAST(ms_get_sealed_data_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_encrypt_data = ms->ms_encrypt_data;
	size_t _len_encrypt_data = ms->ms_encrypt_data_len ;
	char* _in_encrypt_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypt_data, _len_encrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypt_data != NULL && _len_encrypt_data != 0) {
		_in_encrypt_data = (char*)malloc(_len_encrypt_data);
		if (_in_encrypt_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypt_data, _len_encrypt_data, _tmp_encrypt_data, _len_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_encrypt_data[_len_encrypt_data - 1] = '\0';
		if (_len_encrypt_data != strlen(_in_encrypt_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = get_sealed_data_size(_in_encrypt_data);

err:
	if (_in_encrypt_data) free(_in_encrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_data_t* ms = SGX_CAST(ms_seal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	char* _tmp_encrypt_data = ms->ms_encrypt_data;
	size_t _len_encrypt_data = ms->ms_encrypt_data_len ;
	char* _in_encrypt_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_encrypt_data, _len_encrypt_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}
	if (_tmp_encrypt_data != NULL && _len_encrypt_data != 0) {
		_in_encrypt_data = (char*)malloc(_len_encrypt_data);
		if (_in_encrypt_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypt_data, _len_encrypt_data, _tmp_encrypt_data, _len_encrypt_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_encrypt_data[_len_encrypt_data - 1] = '\0';
		if (_len_encrypt_data != strlen(_in_encrypt_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = seal_data(_in_sealed_blob, _tmp_data_size, _in_encrypt_data);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_encrypt_data) free(_in_encrypt_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_state_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_state_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_state_size_t* ms = SGX_CAST(ms_get_sealed_state_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_sealed_state_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_dellist_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_dellist_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_dellist_size_t* ms = SGX_CAST(ms_get_sealed_dellist_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_sealed_dellist_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_state_t* ms = SGX_CAST(ms_seal_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}

	ms->ms_retval = seal_state(_in_sealed_blob, _tmp_data_size);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_DList(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_DList_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_DList_t* ms = SGX_CAST(ms_seal_DList_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}

	ms->ms_retval = seal_DList(_in_sealed_blob, _tmp_data_size);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_state_t* ms = SGX_CAST(ms_unseal_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	size_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = unseal_state((const uint8_t*)_in_sealed_blob, _tmp_data_size);

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_dellist(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_dellist_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_dellist_t* ms = SGX_CAST(ms_unseal_dellist_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	size_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = unseal_dellist((const uint8_t*)_in_sealed_blob, _tmp_data_size);

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

static sgx_status_t SGX_CDECL sgx_parsekey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_parsekey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_parsekey_t* ms = SGX_CAST(ms_parsekey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = parsekey();


	return status;
}

static sgx_status_t SGX_CDECL sgx_insertidx(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_insertidx_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_insertidx_t* ms = SGX_CAST(ms_insertidx_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_keyword = ms->ms_keyword;
	int _tmp_keysize = ms->ms_keysize;
	size_t _len_keyword = _tmp_keysize;
	char* _in_keyword = NULL;
	char* _tmp_BlockInd = ms->ms_BlockInd;
	int _tmp_lengthInd = ms->ms_lengthInd;
	size_t _len_BlockInd = _tmp_lengthInd;
	char* _in_BlockInd = NULL;
	char* _tmp_BlockW = ms->ms_BlockW;
	int _tmp_lengthW = ms->ms_lengthW;
	size_t _len_BlockW = _tmp_lengthW;
	char* _in_BlockW = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);
	CHECK_UNIQUE_POINTER(_tmp_BlockInd, _len_BlockInd);
	CHECK_UNIQUE_POINTER(_tmp_BlockW, _len_BlockW);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_BlockInd != NULL && _len_BlockInd != 0) {
		if ( _len_BlockInd % sizeof(*_tmp_BlockInd) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_BlockInd = (char*)malloc(_len_BlockInd)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_BlockInd, 0, _len_BlockInd);
	}
	if (_tmp_BlockW != NULL && _len_BlockW != 0) {
		if ( _len_BlockW % sizeof(*_tmp_BlockW) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_BlockW = (char*)malloc(_len_BlockW)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_BlockW, 0, _len_BlockW);
	}

	ms->ms_retval = insertidx(_in_keyword, _tmp_keysize, ms->ms_id, _in_BlockInd, _tmp_lengthInd, _in_BlockW, _tmp_lengthW);
	if (_in_BlockInd) {
		if (memcpy_s(_tmp_BlockInd, _len_BlockInd, _in_BlockInd, _len_BlockInd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_BlockW) {
		if (memcpy_s(_tmp_BlockW, _len_BlockW, _in_BlockW, _len_BlockW)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_keyword) free(_in_keyword);
	if (_in_BlockInd) free(_in_BlockInd);
	if (_in_BlockW) free(_in_BlockW);
	return status;
}

static sgx_status_t SGX_CDECL sgx_genLabelInd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_genLabelInd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_genLabelInd_t* ms = SGX_CAST(ms_genLabelInd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ind = ms->ms_ind;
	int _tmp_lencind = ms->ms_lencind;
	size_t _len_ind = _tmp_lencind;
	char* _in_ind = NULL;
	char* _tmp_labelInd = ms->ms_labelInd;
	int _tmp_lenlabelInd = ms->ms_lenlabelInd;
	size_t _len_labelInd = _tmp_lenlabelInd;
	char* _in_labelInd = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ind, _len_ind);
	CHECK_UNIQUE_POINTER(_tmp_labelInd, _len_labelInd);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ind != NULL && _len_ind != 0) {
		if ( _len_ind % sizeof(*_tmp_ind) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ind = (char*)malloc(_len_ind);
		if (_in_ind == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ind, _len_ind, _tmp_ind, _len_ind)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_labelInd != NULL && _len_labelInd != 0) {
		if ( _len_labelInd % sizeof(*_tmp_labelInd) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_labelInd = (char*)malloc(_len_labelInd)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_labelInd, 0, _len_labelInd);
	}

	ms->ms_retval = genLabelInd(_in_ind, _tmp_lencind, _in_labelInd, _tmp_lenlabelInd);
	if (_in_labelInd) {
		if (memcpy_s(_tmp_labelInd, _len_labelInd, _in_labelInd, _len_labelInd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ind) free(_in_ind);
	if (_in_labelInd) free(_in_labelInd);
	return status;
}

static sgx_status_t SGX_CDECL sgx_genlabelw(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_genlabelw_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_genlabelw_t* ms = SGX_CAST(ms_genlabelw_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_labelwStar = ms->ms_labelwStar;
	int _tmp_lenStar = ms->ms_lenStar;
	size_t _len_labelwStar = _tmp_lenStar;
	char* _in_labelwStar = NULL;
	char* _tmp_ind = ms->ms_ind;
	int _tmp_lencind = ms->ms_lencind;
	size_t _len_ind = _tmp_lencind;
	char* _in_ind = NULL;
	char* _tmp_labelw = ms->ms_labelw;
	int _tmp_lenw = ms->ms_lenw;
	size_t _len_labelw = _tmp_lenw;
	char* _in_labelw = NULL;
	char* _tmp_BlockDel = ms->ms_BlockDel;
	int _tmp_lenbdel = ms->ms_lenbdel;
	size_t _len_BlockDel = _tmp_lenbdel;
	char* _in_BlockDel = NULL;
	char* _tmp_wdellabel = ms->ms_wdellabel;
	int _tmp_wdellen = ms->ms_wdellen;
	size_t _len_wdellabel = _tmp_wdellen;
	char* _in_wdellabel = NULL;

	CHECK_UNIQUE_POINTER(_tmp_labelwStar, _len_labelwStar);
	CHECK_UNIQUE_POINTER(_tmp_ind, _len_ind);
	CHECK_UNIQUE_POINTER(_tmp_labelw, _len_labelw);
	CHECK_UNIQUE_POINTER(_tmp_BlockDel, _len_BlockDel);
	CHECK_UNIQUE_POINTER(_tmp_wdellabel, _len_wdellabel);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_labelwStar != NULL && _len_labelwStar != 0) {
		if ( _len_labelwStar % sizeof(*_tmp_labelwStar) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_labelwStar = (char*)malloc(_len_labelwStar);
		if (_in_labelwStar == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_labelwStar, _len_labelwStar, _tmp_labelwStar, _len_labelwStar)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ind != NULL && _len_ind != 0) {
		if ( _len_ind % sizeof(*_tmp_ind) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ind = (char*)malloc(_len_ind);
		if (_in_ind == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ind, _len_ind, _tmp_ind, _len_ind)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_labelw != NULL && _len_labelw != 0) {
		if ( _len_labelw % sizeof(*_tmp_labelw) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_labelw = (char*)malloc(_len_labelw)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_labelw, 0, _len_labelw);
	}
	if (_tmp_BlockDel != NULL && _len_BlockDel != 0) {
		if ( _len_BlockDel % sizeof(*_tmp_BlockDel) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_BlockDel = (char*)malloc(_len_BlockDel)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_BlockDel, 0, _len_BlockDel);
	}
	if (_tmp_wdellabel != NULL && _len_wdellabel != 0) {
		if ( _len_wdellabel % sizeof(*_tmp_wdellabel) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_wdellabel = (char*)malloc(_len_wdellabel)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_wdellabel, 0, _len_wdellabel);
	}

	ms->ms_retval = genlabelw(_in_labelwStar, _tmp_lenStar, _in_ind, _tmp_lencind, _in_labelw, _tmp_lenw, _in_BlockDel, _tmp_lenbdel, _in_wdellabel, _tmp_wdellen);
	if (_in_labelw) {
		if (memcpy_s(_tmp_labelw, _len_labelw, _in_labelw, _len_labelw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_BlockDel) {
		if (memcpy_s(_tmp_BlockDel, _len_BlockDel, _in_BlockDel, _len_BlockDel)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_wdellabel) {
		if (memcpy_s(_tmp_wdellabel, _len_wdellabel, _in_wdellabel, _len_wdellabel)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_labelwStar) free(_in_labelwStar);
	if (_in_ind) free(_in_ind);
	if (_in_labelw) free(_in_labelw);
	if (_in_BlockDel) free(_in_BlockDel);
	if (_in_wdellabel) free(_in_wdellabel);
	return status;
}

static sgx_status_t SGX_CDECL sgx_genLabeldel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_genLabeldel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_genLabeldel_t* ms = SGX_CAST(ms_genLabeldel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_keyword = ms->ms_keyword;
	int _tmp_lenword = ms->ms_lenword;
	size_t _len_keyword = _tmp_lenword;
	char* _in_keyword = NULL;
	char* _tmp_strdel = ms->ms_strdel;
	int _tmp_lendel = ms->ms_lendel;
	size_t _len_strdel = _tmp_lendel;
	char* _in_strdel = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);
	CHECK_UNIQUE_POINTER(_tmp_strdel, _len_strdel);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_strdel != NULL && _len_strdel != 0) {
		if ( _len_strdel % sizeof(*_tmp_strdel) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_strdel = (char*)malloc(_len_strdel)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_strdel, 0, _len_strdel);
	}

	ms->ms_retval = genLabeldel(_in_keyword, _tmp_lenword, _in_strdel, _tmp_lendel);
	if (_in_strdel) {
		if (memcpy_s(_tmp_strdel, _len_strdel, _in_strdel, _len_strdel)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_keyword) free(_in_keyword);
	if (_in_strdel) free(_in_strdel);
	return status;
}

static sgx_status_t SGX_CDECL sgx_GetLabelRes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_GetLabelRes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_GetLabelRes_t* ms = SGX_CAST(ms_GetLabelRes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_keyword = ms->ms_keyword;
	int _tmp_lenword = ms->ms_lenword;
	size_t _len_keyword = _tmp_lenword;
	char* _in_keyword = NULL;
	char* _tmp_labelSetOut = ms->ms_labelSetOut;
	int _tmp_lenOut = ms->ms_lenOut;
	size_t _len_labelSetOut = _tmp_lenOut;
	char* _in_labelSetOut = NULL;
	char* _tmp_labelRes = ms->ms_labelRes;
	int _tmp_lenlres = ms->ms_lenlres;
	size_t _len_labelRes = _tmp_lenlres;
	char* _in_labelRes = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);
	CHECK_UNIQUE_POINTER(_tmp_labelSetOut, _len_labelSetOut);
	CHECK_UNIQUE_POINTER(_tmp_labelRes, _len_labelRes);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_labelSetOut != NULL && _len_labelSetOut != 0) {
		if ( _len_labelSetOut % sizeof(*_tmp_labelSetOut) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_labelSetOut = (char*)malloc(_len_labelSetOut);
		if (_in_labelSetOut == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_labelSetOut, _len_labelSetOut, _tmp_labelSetOut, _len_labelSetOut)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_labelRes != NULL && _len_labelRes != 0) {
		if ( _len_labelRes % sizeof(*_tmp_labelRes) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_labelRes = (char*)malloc(_len_labelRes)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_labelRes, 0, _len_labelRes);
	}

	ms->ms_retval = GetLabelRes(_in_keyword, _tmp_lenword, _in_labelSetOut, _tmp_lenOut, _in_labelRes, _tmp_lenlres);
	if (_in_labelRes) {
		if (memcpy_s(_tmp_labelRes, _len_labelRes, _in_labelRes, _len_labelRes)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_keyword) free(_in_keyword);
	if (_in_labelSetOut) free(_in_labelSetOut);
	if (_in_labelRes) free(_in_labelRes);
	return status;
}

static sgx_status_t SGX_CDECL sgx_getInd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getInd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getInd_t* ms = SGX_CAST(ms_getInd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_keyword = ms->ms_keyword;
	int _tmp_lenword = ms->ms_lenword;
	size_t _len_keyword = _tmp_lenword;
	char* _in_keyword = NULL;
	char* _tmp_res = ms->ms_res;
	int _tmp_len = ms->ms_len;
	size_t _len_res = _tmp_len;
	char* _in_res = NULL;
	char* _tmp_ids = ms->ms_ids;
	int _tmp_idlen = ms->ms_idlen;
	size_t _len_ids = _tmp_idlen;
	char* _in_ids = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);
	CHECK_UNIQUE_POINTER(_tmp_ids, _len_ids);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ( _len_res % sizeof(*_tmp_res) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_res = (char*)malloc(_len_res);
		if (_in_res == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_res, _len_res, _tmp_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ids != NULL && _len_ids != 0) {
		if ( _len_ids % sizeof(*_tmp_ids) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ids = (char*)malloc(_len_ids)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ids, 0, _len_ids);
	}

	ms->ms_retval = getInd(_in_keyword, _tmp_lenword, _in_res, _tmp_len, _in_ids, _tmp_idlen);
	if (_in_ids) {
		if (memcpy_s(_tmp_ids, _len_ids, _in_ids, _len_ids)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_keyword) free(_in_keyword);
	if (_in_res) free(_in_res);
	if (_in_ids) free(_in_ids);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[16];
} g_ecall_table = {
	16,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_seal_data, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_state_size, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_dellist_size, 0, 0},
		{(void*)(uintptr_t)sgx_seal_state, 0, 0},
		{(void*)(uintptr_t)sgx_seal_DList, 0, 0},
		{(void*)(uintptr_t)sgx_unseal_state, 0, 0},
		{(void*)(uintptr_t)sgx_unseal_dellist, 0, 0},
		{(void*)(uintptr_t)sgx_parsekey, 0, 0},
		{(void*)(uintptr_t)sgx_insertidx, 0, 0},
		{(void*)(uintptr_t)sgx_genLabelInd, 0, 0},
		{(void*)(uintptr_t)sgx_genlabelw, 0, 0},
		{(void*)(uintptr_t)sgx_genLabeldel, 0, 0},
		{(void*)(uintptr_t)sgx_GetLabelRes, 0, 0},
		{(void*)(uintptr_t)sgx_getInd, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][16];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_insertidx_err(char* err)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_err = err ? strlen(err) + 1 : 0;

	ms_ocall_insertidx_err_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_insertidx_err_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(err, _len_err);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (err != NULL) ? _len_err : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_insertidx_err_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_insertidx_err_t));
	ocalloc_size -= sizeof(ms_ocall_insertidx_err_t);

	if (err != NULL) {
		ms->ms_err = (char*)__tmp;
		if (_len_err % sizeof(*err) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, err, _len_err)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_err);
		ocalloc_size -= _len_err;
	} else {
		ms->ms_err = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}


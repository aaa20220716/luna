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
#include <stdlib.h>
#include <string.h>
#include <stdexcept>
#include <string>

#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h> 


#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave_init.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_t.h>

uint8_t g_secret[8] = {0};

#ifdef SUPPLIED_KEY_DERIVATION

#pragma message("Supplied key derivation function is used.")

bool derive_key(const sgx_ec256_dh_shared_t* p_shared_key, uint8_t key_id,
                sgx_ec_key_128bit_t* first_derived_key,
                sgx_ec_key_128bit_t* second_derived_key) {
  sgx_status_t sgx_ret = SGX_SUCCESS;
  hash_buffer_t hash_buffer;
  sgx_sha_state_handle_t sha_context;
  sgx_sha256_hash_t key_material;

  memset(&hash_buffer, 0, sizeof(hash_buffer_t));
  hash_buffer.counter[3] = key_id;

  for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++) {
    hash_buffer.shared_secret.s[i] =
        p_shared_key->s[sizeof(p_shared_key->s) - 1 - i];
  }

  sgx_ret = sgx_sha256_init(&sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t),
                              sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_close(sha_context);

  assert(sizeof(sgx_ec_key_128bit_t) * 2 == sizeof(sgx_sha256_hash_t));
  memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
  memcpy(second_derived_key,
         (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t),
         sizeof(sgx_ec_key_128bit_t));
  memset(&key_material, 0, sizeof(sgx_sha256_hash_t));
  return true;
}

#define ISV_KDF_ID 2

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id, sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key) {
  bool derive_ret = false;

  if (NULL == shared_key) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  if (ISV_KDF_ID != kdf_id) {
    return SGX_ERROR_KDF_MISMATCH;
  }

  derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK, smk_key, sk_key);
  if (derive_ret != true) {
    return SGX_ERROR_UNEXPECTED;
  }

  derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK, mk_key, vk_key);
  if (derive_ret != true) {
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}
#else
#pragma message("Default key derivation function is used.")
#endif


sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context) {
  sgx_status_t ret;
#ifdef SUPPLIED_KEY_DERIVATION
  ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
  ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
  printf("In enclave: Initializing the remote attestation context...");
  return ret;
}

sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context) {
  sgx_status_t ret;
  ret = sgx_ra_close(context);
  return ret;
}

sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* p_message,
                                   size_t message_size, uint8_t* p_mac,
                                   size_t mac_size) {
  sgx_status_t ret;
  sgx_ec_key_128bit_t mk_key;

  if (mac_size != sizeof(sgx_mac_t)) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  if (message_size > UINT32_MAX) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  do {
    uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }
    ret = sgx_rijndael128_cmac_msg(&mk_key, p_message, (uint32_t)message_size,
                                   &mac);
    if (SGX_SUCCESS != ret) {
      break;
    }
    if (0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
      ret = SGX_ERROR_MAC_MISMATCH;
      break;
    }

  } while (0);

  return ret;
}

sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t* p_secret,
                             uint32_t secret_size, uint8_t* p_gcm_mac) {
  sgx_status_t ret = SGX_SUCCESS;
  sgx_ec_key_128bit_t sk_key;

  do {
    if (secret_size != 8) {
      ret = SGX_ERROR_INVALID_PARAMETER;
      break;
    }

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(
        &sk_key, p_secret, secret_size, &g_secret[0], &aes_gcm_iv[0], 12, NULL,
        0, (const sgx_aes_gcm_128bit_tag_t*)(p_gcm_mac));

    uint32_t i;
    bool secret_match = true;
    for (i = 0; i < secret_size; i++) {
      if (g_secret[i] != i) {
        secret_match = false;
      }
    }

    if (!secret_match) {
      ret = SGX_ERROR_UNEXPECTED;
    }
  } while (0);
  return ret;
}

sgx_status_t verify_secret_data(sgx_ra_context_t context, uint8_t* p_secret,
                                uint32_t secret_size, uint8_t* p_gcm_mac,
                                uint32_t max_verification_length,
                                uint8_t* p_ret) {
  sgx_status_t ret = SGX_SUCCESS;
  sgx_ec_key_128bit_t sk_key;

  do {
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }

    uint8_t* decrypted = (uint8_t*)malloc(sizeof(uint8_t) * secret_size);
    uint8_t aes_gcm_iv[12] = {0};

    ret = sgx_rijndael128GCM_decrypt(
        &sk_key, p_secret, secret_size, decrypted, &aes_gcm_iv[0], 12, NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)(p_gcm_mac));

    if (SGX_SUCCESS == ret) {
      if (decrypted[0] == 0) {
        if (decrypted[1] != 1) {
          ret = SGX_ERROR_INVALID_SIGNATURE;
        }
      } else {
        ret = SGX_ERROR_UNEXPECTED;
      }
    }
  } while (0);
  return ret;
}

static uint32_t uniform_random_helper(const uint32_t& lower,
                                      const uint32_t& upper) {
  uint32_t random_number;
  // Read a random number.
  sgx_read_rand((unsigned char*)&random_number, 4);
  random_number = random_number % (upper + 1 - lower) + lower;
  return random_number;
}

uint32_t uniform_random(uint32_t lower, uint32_t upper) {
  return uniform_random_helper(lower, upper);
}

int ecall_init_sse_controller() {
  std::string lhs = "0123456789abcdef1234567890abcdef";
  std::string rhs = "0123456789abcdef1234567890abcdef";
  uint8_t out[32] = {0};
  band((uint8_t*)(lhs.data()), (uint8_t*)(rhs.data()), out);
  sprintf(std::string(reinterpret_cast<char*>(out), 32), false);
  const std::string cipher = crypto_manager->enclave_aes_128_gcm_encrypt(
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis eget ");
  sprintf(cipher, true);
  sprintf(crypto_manager->enclave_aes_128_gcm_decrypt(cipher));
  return SGX_SUCCESS;
}

sgx_status_t ecall_begin_DHKE() {
  sgx_status_t status =
      sgx_ecc256_open_context(crypto_manager->get_state_handle());
  return status;
}

sgx_status_t ecall_sample_key_pair(uint8_t* pubkey, size_t pubkey_size) {
  sgx_status_t status = sgx_ecc256_create_key_pair(
      crypto_manager->get_secret_key(), crypto_manager->get_public_key(),
      *crypto_manager->get_state_handle());
  memcpy(pubkey, crypto_manager->get_public_key(), sizeof(sgx_ec256_public_t));

  std::string pk =
      std::move(hex_to_string((uint8_t*)(crypto_manager->get_public_key()),
                              sizeof(sgx_ec256_public_t)));
  std::string sk = std::move(hex_to_string(
      (uint8_t*)(crypto_manager->get_secret_key()), SGX_ECP256_KEY_SIZE));
  printf("Key pair sampled! PK: %s, SK: %s", pk.data(), sk.data());
  return status;
}

sgx_status_t ecall_compute_shared_key(const uint8_t* pubkey,
                                      size_t pubkey_size) {
  sgx_ec256_dh_shared_t shared_key;
  sgx_ec256_public_t client_public_key;
  memcpy(&client_public_key, pubkey, sizeof(sgx_ec256_public_t));

  std::string pub = std::move(hex_to_string((uint8_t*)(&client_public_key),
                                            sizeof(sgx_ec256_public_t)));
  printf("Client public key: %s", pub.data());

  sgx_status_t status = sgx_ecc256_compute_shared_dhkey(
      crypto_manager->get_secret_key(), &client_public_key, &shared_key,
      *crypto_manager->get_state_handle());
  std::string shared =
      std::move(hex_to_string((uint8_t*)(&shared_key), SGX_ECP256_KEY_SIZE));
  printf("Shared key computed: %s", shared.data());

  sgx_ec_key_128bit_t first_derived_key;
  sgx_ec_key_128bit_t second_derived_key;

  if (!derive_key(&shared_key, 0u, &first_derived_key, &second_derived_key)) {
    printf("Cannot derive the session key!");
    return SGX_ERROR_UNEXPECTED;
  }
  crypto_manager->set_shared_key(&second_derived_key);
  printf("The session key is established! The key is %s",
         hex_to_string((uint8_t*)(&second_derived_key),
                       sizeof(sgx_ec_key_128bit_t))
             .data());
}
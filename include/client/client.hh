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
#ifndef CLIENT_HH
#define CLIENT_HH

#include <memory>
#include <string>
#include <cstring>

#include <messages.grpc.pb.h>
#include <messages.pb.h>
#include <sample_libcrypto/sample_libcrypto.h>
#include <service_provider/service_provider.h>
#include <client/utils.hh>


// Key pairs.
// For our own convenience, the keys are hard-coded in the client.
// These keys are taken from the service provider :)
static const sample_ec256_private_t secret_key = {
    {0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce, 0x3b, 0x66, 0xde,
     0x11, 0x43, 0x9c, 0x87, 0xec, 0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6,
     0xae, 0xea, 0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01}};

static const sample_ec256_public_t public_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf, 0x85, 0xd0, 0x3a,
     0x62, 0x37, 0x30, 0xae, 0xad, 0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60,
     0x73, 0x1d, 0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b, 0x26, 0xee, 0xb7,
     0x41, 0xe7, 0xc6, 0x14, 0xe2, 0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2,
     0x9a, 0x28, 0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};



class Client final : public sse::sgx_sse::Service {
 private:
  std::unique_ptr<sse::sgx_sse::Stub> stub_;
  

  // The secrey key.
  sample_ec_key_128bit_t secret_key_session;

  unsigned char m_userKey [16];

  unsigned char kT [16];
  unsigned char ivT [16];

  unsigned char kV [16];
  unsigned char ivV [16];

  

 public:
  Client(const std::string& address, const std::string& port);

  int init_enclave(void);
  int destroy_enclave(void);

  int seal_and_save_state(void);

  int read_and_unseal_state(void);

  int seal_and_save_delset(void);

  int read_and_unseal_delset(void);

  int close_connection(void);

  int generate_session_key(std::string& shared_secret_key);

  int init_sse(void);

  int add_record(std::string shared_secret_key, int ind, std::string w);

  int delete_record(std::string shared_secret_key, int ind, std::string w);

  int search_w(std::string shared_secret_key, std::string w);

};

#endif

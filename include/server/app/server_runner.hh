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
#include <unordered_map>
#include <string>

#include <grpc++/grpc++.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <sgx_urts.h>
#include <sgx_key_exchange.h>

#include <messages.grpc.pb.h>
#include <messages.pb.h>
#include <server/utils.hh>

#define DH_HALF_KEY_LEN 32
#define DH_SHARED_KEY_LEN 32
#define SAMPLE_SP_IV_SIZE 12
#define MAX_VERIFICATION_RESULT 2


class SGXSSEService final : public sse::sgx_sse::Service {
 private:
  std::unordered_map<std::string, std::string> storage;
  std::unordered_map<std::string, std::string> T;
  std::unordered_map<std::string, std::string> V;

  char statefilename[100] = "statefile.txt";
  char delfilename[100] = "delset.txt";

  sgx_status_t init_enclave(sgx_enclave_id_t* const global_eid);
  sgx_status_t seal_and_save_data(sgx_enclave_id_t* const global_eid, std::string filename, bool flag);
  sgx_status_t read_and_unseal_data(sgx_enclave_id_t* const global_eid, std::string filename, bool flag);
  sgx_status_t status;
  sgx_enclave_id_t* const global_eid;
  sgx_ra_context_t context;
  friend class Server;
  sgx_status_t message_handler_round_one(const std::string& message,
                                         sse::InitReply* reply);
  sgx_status_t message_handler_round_two(const std::string& message,
                                         sse::InitReply* reply);
  sgx_status_t message_handler_round_three(const std::string& message,
                                           sse::InitReply* reply);
 public:
  SGXSSEService() = delete;
  SGXSSEService(sgx_enclave_id_t* const global_eid) : global_eid(global_eid) {}
  virtual ~SGXSSEService() override = default;
  grpc::Status init_enclave(grpc::ServerContext* server_context,
                            const sse::InitRequest* init_request,
                            sse::InitReply* init_reply) override;
  grpc::Status destroy_enclave(grpc::ServerContext* server_context,
                                          const sse::DestroyRequest* request,
                                          sse::DestroyReply* reply);
  grpc::Status seal_and_save_data(grpc::ServerContext* server_context,
                                  const sse::SealRequest* seal_request,
                                  sse::SealReply* seal_reply);
  grpc::Status read_and_unseal_data(grpc::ServerContext* server_context,
                                    const sse::UnsealRequest* unseal_request,
                                    sse::UnsealReply* unseal_reply);
  grpc::Status generate_session_key(grpc::ServerContext* server_context,
                                    const sse::InitRequest* init_request,
                                    sse::InitReply* init_reply);
  grpc::Status close_connection(grpc::ServerContext* server_context,
                                const sse::CloseRequest* close_request,
                                google::protobuf::Empty* empty) override;

  grpc::Status init_sse(grpc::ServerContext* server_context,
                         const sse::SSEInitRequest* sse_init_request,
                         google::protobuf::Empty* empty) override;
  grpc::Status remote_attestation_begin(
      grpc::ServerContext* server_context,
      const sse::InitialMessage* initial_message,
      sse::Message0* reply) override;

  grpc::Status remote_attestation_msg0(
      grpc::ServerContext* server_context,
      const sse::Message0* message0,
      sse::Message1* reply) override;

  grpc::Status remote_attestation_msg2(
      grpc::ServerContext* server_context,
      const sse::Message2* message2,
      sse::Message3* reply) override;

  grpc::Status remote_attestation_final(
      grpc::ServerContext* server_context,
      const sse::AttestationMessage* message,
      google::protobuf::Empty* empty) override;

  sgx_status_t generate_epid(uint32_t* extended_epid_group_id);

  grpc::Status add_record(grpc::ServerContext* server_context,
                         const sse::AddRecordRequest* sse_add_record,
                         sse::AddRecordReply* sse_add_reply);

  grpc::Status delete_record(grpc::ServerContext* server_context,
                         const sse::DeleteRecordRequest* sse_del_record,
                         sse::DeleteRecordReply* sse_del_reply);

  grpc::Status search_w(grpc::ServerContext* server_context,
                         const sse::SearchwRequest* sse_search_w_request,
                         sse::SearchwReply* sse_search_w_reply);
};

class Server final {
 private:
  std::unique_ptr<grpc::Server> server;
  std::unique_ptr<SGXSSEService> service;
 public:
  Server() = default;
  void run(const std::string& address, sgx_enclave_id_t* const global_eid);
  void store_compressed_slot(const char* const fingerprint,
                             const std::string& compressed_slot);
  std::string get_compressed_slot(const char* const fingerprint) {
    return service->storage[fingerprint];
  }
  bool is_in_storage(const char* const fingerprint) {
    return service->storage.count(fingerprint) > 0;
  }
};
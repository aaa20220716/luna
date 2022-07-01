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
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cmath>

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#include <configs.hh>
#include <service_provider/service_provider.h>
#include <enclave/enclave_u.h>
#include <server/app/server_runner.hh>
#include <plog/Log.h>
#define SECOND_TO_MRCROSECOND (1000000)

std::atomic_bool server_running;

static std::string read_keycert(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  }
  return oss.str();
}

static void assemble_message(const sse::Message2* message,
                             sgx_ra_msg2_t** const msg2) {
  const uint32_t size = message->size();
  sgx_ra_msg2_t* p_ra_message2 = nullptr;
  p_ra_message2 = (sgx_ra_msg2_t*)malloc(size + sizeof(sgx_ra_msg2_t));

  uint8_t pubkey_gx[32];
  uint8_t pubkey_gy[32];
  sgx_ec256_signature_t signature_gb_ga;
  sgx_spid_t spid;

  for (size_t i = 0; i < 32; i++) {
    pubkey_gx[i] = message->public_key_gx(i);
    pubkey_gy[i] = message->public_key_gy(i);
  }
  for (size_t i = 0; i < 16; i++) {
    spid.id[i] = message->spid(i);
  }
  for (size_t i = 0; i < 8; i++) {
    signature_gb_ga.x[i] = message->signature_x(i);
    signature_gb_ga.y[i] = message->signature_y(i);
  }

  memcpy(&p_ra_message2->g_b.gx, &pubkey_gx, sizeof(pubkey_gx));
  memcpy(&p_ra_message2->g_b.gy, &pubkey_gy, sizeof(pubkey_gy));
  memcpy(&p_ra_message2->sign_gb_ga, &signature_gb_ga, sizeof(signature_gb_ga));
  memcpy(&p_ra_message2->spid, &spid, sizeof(spid));

  p_ra_message2->quote_type = static_cast<uint16_t>(message->quote_type());
  p_ra_message2->kdf_id = message->cmac_kdf_id();

  uint8_t smac[16];
  for (size_t i = 0; i < 16; i++) {
    smac[i] = message->smac(i);
  }
  memcpy(&p_ra_message2->mac, &smac, sizeof(smac));

  p_ra_message2->sig_rl_size = message->size_sigrl();
  uint8_t* sigrl = (uint8_t*)malloc(message->size_sigrl() * sizeof(uint8_t));
  for (size_t i = 0; i < message->size_sigrl(); i++) {
    sigrl[i] = message->sigrl(i);
  }
  memcpy(&p_ra_message2->sig_rl, &sigrl, message->size_sigrl());

  *msg2 = p_ra_message2;
}

static void assemble_attestation_message(
    const sse::AttestationMessage* message,
    ra_samp_response_header_t** pp_att_msg) {
  const size_t total_size = message->size() + message->result_size() +
                            sizeof(ra_samp_response_header_t);
  sample_ra_att_result_msg_t* p_att_result_msg = nullptr;
  ra_samp_response_header_t* p_att_result_msg_full = nullptr;

  p_att_result_msg_full = (ra_samp_response_header_t*)malloc(total_size);
  memset(p_att_result_msg_full, 0, total_size);
  p_att_result_msg_full->size = message->size();

  p_att_result_msg = reinterpret_cast<sample_ra_att_result_msg_t*>(
      p_att_result_msg_full->body);
  p_att_result_msg->platform_info_blob.sample_epid_group_status =
      message->epid_group_status();
  p_att_result_msg->platform_info_blob.sample_tcb_evaluation_status =
      message->tcb_evaluation_status();
  p_att_result_msg->platform_info_blob.pse_evaluation_status =
      message->pse_evaluation_status();

  for (size_t i = 0; i < PSVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_equivalent_tcb_psvn[i] =
        message->latest_equivalent_tcb_psvn(i);
  }
  for (size_t i = 0; i < ISVSVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_pse_isvsvn[i] =
        message->latest_pse_isvsvn(i);
  }
  for (size_t i = 0; i < PSDA_SVN_SIZE; i++) {
    p_att_result_msg->platform_info_blob.latest_psda_svn[i] =
        message->latest_psda_svn(i);
  }
  for (size_t i = 0; i < GID_SIZE; i++) {
    p_att_result_msg->platform_info_blob.performance_rekey_gid[i] =
        message->performance_rekey_gid(i);
  }
  for (size_t i = 0; i < SAMPLE_NISTP256_KEY_SIZE; i++) {
    p_att_result_msg->platform_info_blob.signature.x[i] =
        message->ec_sign256_x(i);
    p_att_result_msg->platform_info_blob.signature.y[i] =
        message->ec_sign256_y(i);
  }
  for (size_t i = 0; i < SAMPLE_MAC_SIZE; i++) {
    p_att_result_msg->mac[i] = message->mac_smk(i);
  }

  p_att_result_msg->secret.payload_size = message->result_size();
  for (size_t i = 0; i < 12; i++) {
    p_att_result_msg->secret.reserved[i] = message->reserved(i);
  }
  for (size_t i = 0; i < SAMPLE_SP_TAG_SIZE; i++) {
    p_att_result_msg->secret.payload_tag[i] = message->payload_tag(i);
  }
  for (size_t i = 0; i < message->result_size(); i++) {
    p_att_result_msg->secret.payload[i] =
        static_cast<uint8_t>(message->payload(i));
  }

  *pp_att_msg = p_att_result_msg_full;
}

grpc::Status SGXSSEService::init_enclave(grpc::ServerContext* server_context,
                                          const sse::InitRequest* init_request,
                                          sse::InitReply* init_reply) {
  const uint32_t round = init_request->round();
  if (round == 0) {
    LOG(plog::info) << "Trying to initialize the enclave with id "
                    << *global_eid;
    if (init_enclave(global_eid) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot be initialized!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
      enclave_init_ra(*global_eid, &status, false, &context);

      if (status != SGX_SUCCESS) {
        const std::string error_message = "Remote attestation failed!";
        return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
      } else{
        init_reply->set_success(true);
      }
      return grpc::Status::OK;
    }
  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXSSEService::destroy_enclave(grpc::ServerContext* server_context,
                                          const sse::DestroyRequest* request,
                                          sse::DestroyReply* reply) {
    LOG(plog::info) << "Trying to destroy the enclave with id "
                    << *global_eid;
    if (sgx_sse::destroy_enclave(global_eid)) {
      const std::string error_message = "Enclave cannot be destroied!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
        reply->set_success(true);
    }
      return grpc::Status::OK;
}

grpc::Status SGXSSEService::seal_and_save_data(grpc::ServerContext* server_context,
                                              const sse::SealRequest* seal_request,
                                              sse::SealReply* seal_reply) {
  bool flag = seal_request->type();
  std::string seal_data_file = seal_request->address();
  LOG(plog::info) << "Trying to seal the enclave with id "
                  << *global_eid;
  if (seal_and_save_data(global_eid, seal_data_file, flag) != SGX_SUCCESS) {
    const std::string error_message = "Enclave cannot be seal";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } 
  seal_reply->set_success(true);
  return grpc::Status::OK;
}

grpc::Status SGXSSEService::read_and_unseal_data(grpc::ServerContext* server_context,
                                              const sse::UnsealRequest* unseal_request,
                                              sse::UnsealReply* unseal_reply) {
  bool flag = unseal_request->type();
  std::string unseal_data_file = unseal_request->address();
  LOG(plog::info) << "Trying to unseal the enclave with id "
                  << *global_eid;
  if (read_and_unseal_data(global_eid, unseal_data_file, flag) != SGX_SUCCESS) {
    const std::string error_message = "Enclave cannot be unseal";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } 
  unseal_reply->set_success(true);
  return grpc::Status::OK;
}

grpc::Status SGXSSEService::generate_session_key(
    grpc::ServerContext* server_context, const sse::InitRequest* init_request,
    sse::InitReply* init_reply) {
  const uint32_t round = init_request->round();
  LOG(plog::info) << "Begin to generate DH key pair...";
  if (round == 1u) {
    if (ecall_begin_DHKE(*global_eid, &status) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot create an ECC state!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }
    uint8_t pk[sizeof(sgx_ec256_public_t)];
    if (ecall_sample_key_pair(*global_eid, &status, pk,
                              sizeof(sgx_ec256_public_t)) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot sample the key pair!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }
    init_reply->set_content(
        std::string((char*)&pk, sizeof(sgx_ec256_public_t)));
    return grpc::Status::OK;
  } else if (round == 2) {
    const std::string client_pk = init_request->content();
    LOG(plog::debug) << "In server runner: "
                     << sgx_sse::hex_to_string((uint8_t*)(client_pk.data()),
                                                64);

    if (ecall_compute_shared_key(*global_eid, &status,
                                 (const uint8_t*)client_pk.data(),
                                 client_pk.size()) != SGX_SUCCESS) {
      const std::string error_message =
          "Enclave cannot compute the shared key! The key is possibly "
          "corrupted!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }
    return grpc::Status::OK;
  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXSSEService::close_connection(
    grpc::ServerContext* server_context,
    const sse::CloseRequest* close_request, google::protobuf::Empty* empty) {
    LOG(plog::info) << server_context->peer() << " - Closing connection... Goodbye!";
    server_running = false;
    return grpc::Status::OK;
}

grpc::Status SGXSSEService::remote_attestation_begin(
    grpc::ServerContext* server_context,
    const sse::InitialMessage* initial_message, sse::Message0* reply) {
  LOG(plog::info) << "Begin remote attestation...";
  LOG(plog::info) << "The server is generating the epid group id...";

  uint32_t extended_epid_group_id;
  status = sgx_get_extended_epid_group_id(&extended_epid_group_id);

  if (status != SGX_SUCCESS) {
    const std::string error_message = "Failed to generate epid group id!";
    LOG(plog::error) << error_message;
    reply->set_epid(0ul);
    reply->set_status(-1);
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    LOG(plog::info) << "The server has generated the epid group id: "
                    << extended_epid_group_id;
    reply->set_epid(extended_epid_group_id);
    return grpc::Status::OK;
  }
}

grpc::Status SGXSSEService::remote_attestation_msg0(
    grpc::ServerContext* server_context, const sse::Message0* message,
    sse::Message1* reply) {
  LOG(plog::info) << "Received message 0 from the client...";
  LOG(plog::info) << "The server is generating the message 1...";

  sgx_ra_msg1_t ra_message1;
  status = sgx_ra_get_msg1(context, *global_eid, sgx_ra_get_ga, &ra_message1);

  if (status != SGX_SUCCESS) {
    const std::string error_message = "Failed to generate message 1!";
    LOG(plog::error) << error_message;
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    for (size_t i = 0; i < 32; i++) {
      reply->add_gax(ra_message1.g_a.gx[i]);
      reply->add_gay(ra_message1.g_a.gy[i]);
      reply->add_gid(ra_message1.gid[i]);
    }
    return grpc::Status::OK;
  }
}

grpc::Status SGXSSEService::remote_attestation_msg2(
    grpc::ServerContext* server_context, const sse::Message2* message,
    sse::Message3* reply) {
  LOG(plog::info) << "Received message 2 from the client.";
  LOG(plog::info) << "The server is generating the message 3...";

  const uint32_t size = message->size();
  sgx_ra_msg2_t* p_ra_message2;
  assemble_message(message, &p_ra_message2);
  LOG(plog::info) << "The server has assembled the message 2.";

  sgx_ra_msg3_t* p_ra_message3 = nullptr;
  uint32_t message3_size;
  uint32_t retries = 5;

  do {
    status = sgx_ra_proc_msg2(context, *global_eid, sgx_ra_proc_msg2_trusted,
                              sgx_ra_get_msg3_trusted, p_ra_message2, size,
                              &p_ra_message3, &message3_size);
  } while (SGX_ERROR_BUSY == status && retries--);

  sgx_sse::safe_free(p_ra_message2);

  if (status != SGX_SUCCESS) {
    const std::string error_message = "Failed to generate message 3!";
    LOG(plog::error) << error_message;
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {
    reply->set_size(message3_size);

    for (size_t i = 0; i < SGX_MAC_SIZE; i++) {
      reply->add_sgx_mac(p_ra_message3->mac[i]);
    }
    for (size_t i = 0; i < SGX_ECP256_KEY_SIZE; i++) {
      reply->add_gax_msg3(p_ra_message3->g_a.gx[i]);
      reply->add_gay_msg3(p_ra_message3->g_a.gy[i]);
    }
    for (size_t i = 0; i < 256; i++) {
      reply->add_sec_property(
          p_ra_message3->ps_sec_prop.sgx_ps_sec_prop_desc[i]);
    }
    for (size_t i = 0; i < 1116; i++) {
      reply->add_quote(p_ra_message3->quote[i]);
    }

    sgx_sse::safe_free(p_ra_message3);
    LOG(plog::info) << "The server has successfully generated the message 3.";
    return grpc::Status::OK;
  }
}

grpc::Status SGXSSEService::remote_attestation_final(
    grpc::ServerContext* server_context,
    const sse::AttestationMessage* message, google::protobuf::Empty* empty) {
  LOG(plog::info) << "Received message 3 from the client.";
  LOG(plog::info)
      << "The server is generating the final attestation message...";

  ra_samp_response_header_t* p_att_result_msg_full = nullptr;
  assemble_attestation_message(message, &p_att_result_msg_full);

  sample_ra_att_result_msg_t* p_att_result_msg_body =
      (sample_ra_att_result_msg_t*)((uint8_t*)p_att_result_msg_full +
                                    sizeof(ra_samp_response_header_t));

  status = verify_att_result_mac(
      *global_eid, &status, context,
      (uint8_t*)&p_att_result_msg_body->platform_info_blob,
      sizeof(ias_platform_info_blob_t), (uint8_t*)&p_att_result_msg_body->mac,
      sizeof(sgx_mac_t));

  if (status != SGX_SUCCESS) {
    const std::string error_message =
        "Failed to verify the attestation result!";
    LOG(plog::error) << error_message;
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else if (p_att_result_msg_full->status[0] != 0 ||
             p_att_result_msg_full->status[1] != 0) {

    const std::string error_message =
        "Attestation mac result message MK based CMAC failed!";
    LOG(plog::error) << error_message;
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  } else {

    status = verify_secret_data(*global_eid, &status, context,
                                p_att_result_msg_body->secret.payload,
                                p_att_result_msg_body->secret.payload_size,
                                p_att_result_msg_body->secret.payload_tag,
                                MAX_VERIFICATION_RESULT, NULL);

    sgx_sse::safe_free(p_att_result_msg_full);

    if (status != SGX_SUCCESS) {
      const std::string error_message = "Failed to verify the secret data!";
      LOG(plog::error) << error_message;
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
      LOG(plog::info) << "The server has successfully verified the secret data. Local attestation OK.";
    }
  }
  sgx_sse::safe_free(p_att_result_msg_full);
  return grpc::Status::OK;
}

grpc::Status SGXSSEService::init_sse(
    grpc::ServerContext* server_context,
    const sse::SSEInitRequest* sse_init_request,
    google::protobuf::Empty* empty) {
  
  LOG(plog::debug) << "The server has properly configured the SSE.";
  return grpc::Status::OK;
}

void Server::store_compressed_slot(const char* const fingerprint,
                                   const std::string& compressed_slot) {
  service->storage[fingerprint] = compressed_slot;
}

void Server::run(const std::string& address,
                 sgx_enclave_id_t* const global_eid) {
  const std::string data_dir = "./data";
  if (mkdir(data_dir.c_str(), 0777) == -1) {
    if (errno != EEXIST) {
      LOG(plog::error) << "Cannot create the directory for storing slots!";
      exit(1);
    }
  }

  service = std::make_unique<SGXSSEService>(global_eid);
  const std::string servercert = read_keycert(key_path + "/" + "sslcred.crt");
  const std::string serverkey = read_keycert(key_path + "/" + "sslcred.key");

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp;
  pkcp.private_key = serverkey;
  pkcp.cert_chain = servercert;

  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = "";
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);

  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::InsecureServerCredentials();

  grpc::ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials());
  builder.RegisterService(service.get());

  server = (builder.BuildAndStart());
  LOG(plog::info) << "Server listening on " << address;
  server_running = true;

  // Start a monitor thread.
  std::thread monitor_thread([&, this]() {
    while (server_running);
    server->Shutdown();
  });
  monitor_thread.detach();
  server->Wait();
}

sgx_status_t SGXSSEService::init_enclave(sgx_enclave_id_t* const global_eid) {
  if (sgx_sse::init_enclave(global_eid) != 0) {
    LOG(plog::error) << "Cannot initialize the enclave!";
  }
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  sgx_status_t retval;

  ecall_init_sse_controller(*global_eid, (int*)&ret);
  return ret;
}

sgx_status_t SGXSSEService::seal_and_save_data(sgx_enclave_id_t* const global_eid, std::string filename, bool flag) {
  sgx_status_t ret;
  uint32_t sealed_data_size = 0;
  if (flag) {
    ret = get_sealed_state_size(*global_eid, &sealed_data_size);
  } else{
    ret = get_sealed_delset_size(*global_eid, &sealed_data_size);
  }
  
  if (ret != SGX_SUCCESS)
  {
    LOG(plog::error) << "Fail to get sealed data size1";
    return ret;
  }
  else if(sealed_data_size == UINT32_MAX)
  {
    LOG(plog::error) << "Fail to get sealed dara size2";
    return ret;
  }
    
  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  if(temp_sealed_buf == NULL)
  {
    LOG(plog::error) << "Out of memory";
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t retval;

  if(flag){
    ret = seal_state(*global_eid, &retval, temp_sealed_buf, sealed_data_size);
  } else {
    ret = seal_delset(*global_eid, &retval, temp_sealed_buf, sealed_data_size);
  }

  if (ret != SGX_SUCCESS)
  {
    free(temp_sealed_buf);
    LOG(plog::error) << "Fail to seal data1";
    return ret;
  }
  else if( retval != SGX_SUCCESS)
  {
    free(temp_sealed_buf);
    LOG(plog::error) << "Fail to seal data2";
    return ret;
  }

  if (sgx_sse::write_buf_to_file((char *)filename.c_str(), temp_sealed_buf, sealed_data_size, 0) == false)
  {
    LOG(plog::error) << "Failed to save the sealed data blob to \"" 
                      << filename;
    free(temp_sealed_buf);
    return SGX_ERROR_UNEXPECTED;
  }

  free(temp_sealed_buf);

  LOG(plog::info) << "Sealing data succeeded.";
  return SGX_SUCCESS;
}

sgx_status_t SGXSSEService::read_and_unseal_data(sgx_enclave_id_t* const global_eid, std::string filename, bool flag) {
  sgx_status_t ret;
  size_t fsize = sgx_sse::get_file_size((char *)filename.c_str());
  if (fsize == (size_t)-1)
  {
    LOG(plog::error) << "Failed to get the file size of \"" 
                      << filename;
    return SGX_ERROR_UNEXPECTED;
  }
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if(temp_buf == NULL)
  {
    LOG(plog::error) << "Out of memory";
    return SGX_ERROR_UNEXPECTED;
  }
  if (sgx_sse::read_file_to_buf((char *)filename.c_str(), temp_buf, fsize) == false)
  {
    LOG(plog::error) << "Failed to read the sealed data blob from \"" 
                      << filename;
    free(temp_buf);
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t retval;
  
  if (flag) {
    ret = unseal_state(*global_eid, &retval, temp_buf, fsize);
  } else {
    ret = unseal_delset(*global_eid, &retval, temp_buf, fsize);
  }
  
  if (ret != SGX_SUCCESS)
  {
    free(temp_buf);
    LOG(plog::error) << "Fial to unseal data1";
    return SGX_ERROR_UNEXPECTED;
  }
  else if(retval != SGX_SUCCESS)
  {
    free(temp_buf);
    LOG(plog::error) << "Fail to unseal data2";
    return SGX_ERROR_UNEXPECTED;
  }

  free(temp_buf);
   
  LOG(plog::info) << "Unseal succeeded.";
  return SGX_SUCCESS;
}

grpc::Status SGXSSEService::add_record(grpc::ServerContext* server_context,
                      const sse::AddRecordRequest* sse_add_request,
                      sse::AddRecordReply* sse_add_reply) 
{
  std::string uT = sse_add_request->ut();
  std::string eT = sse_add_request->et();
  std::string cst = sse_add_request->cst();
  int ind = sse_add_request->ind();
  std::string enc = sse_add_request->enc();

  sgx_status_t ret, retval;

  char *cuV = new char[48]; 
  char *ceV = new char[48];
  ret = ecall_add_gen_V(*global_eid, &retval, 
                    (char *)cst.c_str(), 
                    cst.length(), 
                    cuV, 
                    48, 
                    ceV, 
                    48);
  if (ret != SGX_SUCCESS) {
    LOG(plog::error) << "SGX went wrong";
  } else if (retval != SGX_SUCCESS) {
    LOG(plog::error) <<"SGX went wrong";
  }
  std::string uV = cuV;
  std::string eV = ceV;
  
  sgx_sse::store_idx_val(uT, eT, uV, eV, ind, enc);

  sse_add_reply->set_success(true);
  delete[] cuV;
  delete[] ceV;
                        
  return grpc::Status::OK;
}
grpc::Status SGXSSEService::delete_record(grpc::ServerContext* server_context,
                         const sse::DeleteRecordRequest* sse_del_request,
                         sse::DeleteRecordReply* sse_del_reply) 
{
  std::string cst = sse_del_request->cst();
  int ind = sse_del_request->ind();
  sgx_status_t ret, retval;
  char *xV = new char[1024*1024*100];
  
  ret = ecall_del_gen_V(*global_eid, &retval, 
                    (char *)cst.c_str(), 
                    cst.length(), 
                    xV, 
                    1024*1024*100);
  if (ret != SGX_SUCCESS) {
    LOG(plog::error) << "SGX went wrong";
  } else if (retval != SGX_SUCCESS) {
    LOG(plog::error) <<"SGX went wrong";
  }
  std::string eV;
  
  sgx_sse::get_eV((std::string)xV, eV);
  char* uT = new char[64];
  char* uV = new char[64];
  char*flag = new char[2];
  ret = ecall_update_D(*global_eid, &retval, 
                      (char *)cst.c_str(),
                      cst.length(), 
                      (char*)eV.c_str(), 
                      eV.length(),
                      uT,
                      64,
                      uV,
                      64);
  if (ret != SGX_SUCCESS) {
    LOG(plog::error) << "SGX went wrong";
  } else if (retval != SGX_SUCCESS) {
    LOG(plog::error) <<"SGX went wrong";
  }

  sgx_sse::delete_idx_val(uT, uV);
  
  sse_del_reply->set_success(true);

  delete[] xV;
  delete[] uT;
  delete[] uV;
  delete[] flag;
  return grpc::Status::OK;
}

grpc::Status SGXSSEService::search_w(grpc::ServerContext* server_context,
                         const sse::SearchwRequest* sse_search_w_request,
                         sse::SearchwReply* sse_search_w_reply) {
  std::string cst = sse_search_w_request->cst();
  sgx_status_t ret, retval;
  char *xuT = new char[1024*1024*100];
  char *xNum = new char[1024*1024*100];

  ret = ecall_search_w(*global_eid, &retval, 
                      (char *)cst.c_str(),
                      cst.length(),
                      xuT,
                      1024*1024*100,
                      xNum,
                      1024*1024*100);
  if (ret != SGX_SUCCESS) {
    LOG(plog::error) << "SGX went wrong";
  } else if (retval != SGX_SUCCESS) {
    LOG(plog::error) <<"SGX went wrong";
  }

  std::string xeT;
  
  sgx_sse::get_from_edb("tableT", "eT", "uT", xuT, xeT);

  char *xind = new char[1024*1024*100];
  ret = ecall_get_res(*global_eid, &retval,
                      (char *)cst.c_str(),
                      cst.length(),
                      (char*)xeT.c_str(),
                      xeT.length(),
                      xNum, 
                      strlen(xNum),
                      xind,
                      1024*1024*100);
  
  std::string xct;
  sgx_sse::get_from_edb("tableenc", "enc", "ind", xind, xct);

  sse_search_w_reply->set_xct(xct);
  sse_search_w_reply->set_success(true);

  delete[] xuT;
  delete[] xNum;
  delete[] xind;
  return grpc::Status::OK;
}

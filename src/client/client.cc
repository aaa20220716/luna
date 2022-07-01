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
#include <fstream>
#include <sstream>

#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <gflags/gflags.h>

#include <plog/Log.h>
#include <configs.hh>
#include <client/client.hh>
#define SECOND_TO_MRCROSECOND (1000000)
#define SEC_TO_NS (1000000000)

std::unordered_map<std::string, state> client_st;

static std::string read_keycert(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  }
  return oss.str();
}


Client::Client(const std::string& address, const std::string& port) {
  const std::string cacert = read_keycert(key_path + "/" + "sslcred.crt");

  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = cacert;
  std::shared_ptr<grpc::ChannelCredentials> ssl_creds =
      grpc::InsecureChannelCredentials();
  stub_ = sse::sgx_sse::NewStub(std::shared_ptr<grpc::Channel>(
      grpc::CreateChannel(address + ":" + port, ssl_creds)));

  memcpy(m_userKey, "XZJE151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4FTP", USER_KEY_LENGTH);

  memcpy(kT, "shfnekwiahdteghfkapwur63894nbx73h395jh583h367fh3", USER_KEY_LENGTH);
  memcpy(ivT, "936cfbeiw64ghfjqwy2f3tdg4u5784h3h2jdjqvjewk2382365", IVEC_LENGTH);

  memcpy(kV, "tgwikoewjhwbiqwhsd632901hx5374652hdbr", USER_KEY_LENGTH);
  memcpy(ivV, "h236754912hydsxbri32fg125weu854hdf723y438", IVEC_LENGTH);
}

int Client::init_enclave(void) {
  LOG(plog::info) << "Trying to initializing the enclave on the server.";

  grpc::ClientContext context;
  sse::InitRequest request;
  request.set_round(0);
  sse::InitReply reply;
  
  grpc::Status status = stub_->init_enclave(&context, request, &reply);

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has initialized the enclave!";

    return 0;
  }
}
int Client::destroy_enclave(void) {
  LOG(plog::info) << "Trying to destroy the enclave";
  grpc::ClientContext context;
  sse::DestroyRequest request;
  sse::DestroyReply reply;
  grpc::Status status = stub_->destroy_enclave(&context, request, &reply);
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has destroy the enclave!";

    return 0;
  }
}




int Client::add_record(std::string session_key, int ind, std::string w) {
  grpc::ClientContext context;
  sse::AddRecordRequest request;
  sse::AddRecordReply reply;

  std::string secret = w;
  std::string sign = "*";
  secret.append(sign);//w*
  secret.append(std::to_string(ind));//w*ind
  secret.append(sign);//w*ind*

  int aw = 0;
  std::unordered_map<std::string, state>::iterator it = client_st.find(w);
  if (it == client_st.end()) {
    state initSt(0,0);
    client_st.insert(std::make_pair(w, initSt)); 
  } else {
    aw = (it->second).aw;
  }
  secret.append(std::to_string(aw));//w*ind*CW[w]
  secret.append(sign);//w*ind*CW[w]*
  std::string kV = (char*)this->kV;
  std::string ivV = (char*)this->ivV;
  get_kv_ivv(kV, ivV, secret);

  std::string enc_enc_secret;
  gen_enc_secret(session_key, secret, enc_enc_secret);


  std::string h1, h2;
  std::string eT;
  unsigned char* ckT = new unsigned char[17];
  memset(ckT, 0, 17);
  memcpy(ckT, this->kT, 16);
  unsigned char* civT = new unsigned char[17];
  memset(civT, 0, 17);
  memcpy(civT, this->ivT, 16);
  std::string kw = Genkw(ckT, civT, w);
  GenuT(kw, aw, h1, h2);//生成uT=h1

  GeneT(ind, h2, eT);//生成eT

  ClientSt_update(w, client_st, true);

  char *m_ivec = new char[17];
  memset(m_ivec, 0, 17);
  randstr(m_ivec, 16);
  std::string enc = EncryptionAES(this->m_userKey, (unsigned char*)m_ivec, w);
  std::string siv = m_ivec;
  enc.append(siv);

  request.set_ut(h1);//uT
  request.set_et(eT);
  request.set_cst(enc_enc_secret);
  request.set_ind((int32_t)ind);
  request.set_enc(enc);


  grpc::Status status = stub_->add_record(&context, request, &reply);
  delete[] m_ivec;
  
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();
    return -1;
  } else {
    return 0;
  }

}

int Client::close_connection(void) {
  grpc::ClientContext context;
  sse::CloseRequest request;
  google::protobuf::Empty empty;
  stub_->close_connection(&context, request, &empty);

  return 0;
}

int Client::init_sse(void) {
  grpc::ClientContext context;
  sse::SSEInitRequest request;
  

  // Print the log.
  LOG(plog::info) << "Sending parameters of the SSE to the server!";

  google::protobuf::Empty empty;
  stub_->init_sse(&context, request, &empty);

  return 0;
}

int Client::generate_session_key(std::string& session_key) {
  LOG(plog::info) << "Sending negotiated key to the server.";

  grpc::ClientContext context;
  sse::InitRequest request;
  request.set_round(1);
  sse::InitReply reply;

  grpc::Status status = stub_->generate_session_key(&context, request, &reply);

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    const std::string server_pk = reply.content();
    LOG(plog::debug) << "Server's public key received! The pulic key is "
                     << hex_to_string((uint8_t*)server_pk.data(),
                                      server_pk.size());

    sample_ecc_state_handle_t state_handle;
    sample_ecc256_open_context(&state_handle);
    sample_ec256_dh_shared_t shared_key;
    sample_ecc256_compute_shared_dhkey(
        (sample_ec256_private_t*)&secret_key,
        (sample_ec256_public_t*)(server_pk.data()),
        (sample_ec256_dh_shared_t*)&shared_key, state_handle);
    std::string shared_secret_key = hex_to_string((uint8_t*)(&shared_key),
                                     sizeof(sample_ec256_dh_shared_t));
    LOG(plog::info) << "Shared key established! The key is "
                    << shared_secret_key;
    
    grpc::ClientContext ctx;
    sse::InitRequest req;
    req.set_round(2);
    req.set_content(
        std::string((char*)&public_key, sizeof(sample_ec256_public_t)));
    status = stub_->generate_session_key(&ctx, req, &reply);

    if (!status.ok()) {
      LOG(plog::fatal) << status.error_message();
      return -1;
    }

    sample_ec_key_128bit_t smk_key;
    if (!derive_key((sample_ec_dh_shared_t*)&shared_key, 0u, &smk_key,
                    &secret_key_session)) {
      LOG(plog::fatal) << "Cannot derive secret key!";
    }
    session_key = hex_to_string((uint8_t*)(&secret_key_session), sizeof(sample_ec_key_128bit_t));
    LOG(plog::info) << "The session key is established! The key is "
                    << session_key;

    sample_ecc256_close_context(state_handle);
  }
  return 0;
}

int Client::seal_and_save_state(void) {
  grpc::ClientContext context;
  sse::SealRequest request;
  sse::SealReply reply;
  request.set_address("statefile.txt");
  request.set_type(1);
  
  LOG(plog::info) << "Seal and save I to server";

  grpc::Status status = stub_->seal_and_save_data(&context, request, &reply);

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has sealed the state";

    return 0;
  }
}

int Client::seal_and_save_delset(void) {
  grpc::ClientContext context;
  sse::SealRequest request;
  sse::SealReply reply;
  request.set_address("delset.txt");
  request.set_type(0);
  
  LOG(plog::info) << "Seal and save delSet to server";

  grpc::Status status = stub_->seal_and_save_data(&context, request, &reply);
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has sealed the delSet";

    return 0;
  }
}

int Client::read_and_unseal_state(void) {
  grpc::ClientContext context;
  sse::UnsealRequest request;
  sse::UnsealReply reply;
  request.set_address("statefile.txt");
  request.set_type(1);
  
  LOG(plog::info) << "Read and unseal I to enclave";

  grpc::Status status = stub_->read_and_unseal_data(&context, request, &reply);
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has unsealed the state";

    return 0;
  }
}

int Client::read_and_unseal_delset(void) {
  grpc::ClientContext context;
  sse::UnsealRequest request;
  sse::UnsealReply reply;
  request.set_address("delset.txt");
  request.set_type(0);
  
  LOG(plog::info) << "Seal and save delSet to server";

  grpc::Status status = stub_->read_and_unseal_data(&context, request, &reply);
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has unsealed the delSet";

    return 0;
  }
  return 0;
}

int Client::delete_record(std::string session_key, int ind, std::string w) {
  int aw = 0;
  int nw = 0;  
  std::string sign = "*";
  std::unordered_map<std::string, state>::iterator it = client_st.find(w);
  if (it == client_st.end()) { 
    LOG(plog::info) << "Wrong parameter";
  } else {
    aw = (it->second).aw;
    nw = (it->second).nw;
  }
  std::string secret;
  secret = w;
  secret.append(sign);
  secret.append(std::to_string(ind));
  secret.append(sign);

  std::string kT = (char*)this->kT;
  std::string ivT = (char*)this->ivT;
  std::string kV = (char*)this->kV;
  std::string ivV = (char*)this->ivV;
  get_k_iv(kT, ivT, kV, ivV, secret);

  std::string enc_enc_secret;
  gen_enc_secret(session_key, secret, enc_enc_secret);

  ClientSt_update(w, client_st, false);

  grpc::ClientContext context;
  sse::DeleteRecordRequest request;
  sse::DeleteRecordReply reply;

  request.set_cst(enc_enc_secret);
  request.set_ind((int32_t)ind);

  grpc::Status status = stub_->delete_record(&context, request, &reply);
  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();
    return -1;
  } else {
    return 0;
  }
}

int Client::search_w(std::string session_key, std::string w) {
  grpc::ClientContext context;
  sse::SearchwRequest request;
  sse::SearchwReply reply;

  std::string sign = "*";
  std::string secret = w;
  secret.append(sign);//secret = w*
  std::unordered_map<std::string, state>::iterator it = client_st.find(w);
  if (it == client_st.end()) { 
    LOG(plog::error) << "Parameter Error";
    return -1;
  } 
  int nw = (it->second).nw;
  char *cnw = new char[10];
  memset(cnw, 0, 10);
  memcpy(cnw, std::to_string(nw).c_str(), std::to_string(nw).length());
  std::string snw = cnw;
  secret.append(snw);//secret = w*nw
  secret.append(sign);//secret = w*nw*

  unsigned char* ckT = new unsigned char[17];
  memset(ckT, 0, 17);
  memcpy(ckT, this->kT, 16);
  unsigned char* civT = new unsigned char[17];
  memset(civT, 0, 17);
  memcpy(civT, this->ivT, 16);
  std::string kw = Genkw(ckT, civT, w);

  secret.append(kw);
  secret.append(sign);//secret = w*nw*kw*
  std::string enc_enc_secret;
  gen_enc_secret(session_key, secret, enc_enc_secret);
  request.set_cst(enc_enc_secret);

  grpc::Status status = stub_->search_w(&context, request, &reply);
  std::string xct = reply.xct();
  std::vector<std::string>pt;
  get_pt(this->m_userKey, xct, pt);
  LOG(plog::info) << "nw = " << nw;
  for (auto it0:pt) {
    LOG(plog::info) << "pt = " << it0;
  }

  delete[] cnw;
  delete[] ckT;
  delete[] civT;

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();
    return -1;
  } else {
    return 0;
  }
}
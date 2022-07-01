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
#include <client.hh>
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <gflags/gflags.h>


static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log"); 
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  


DEFINE_string(address, "182.92.127.18", "The server's IP address");

DEFINE_string(port, "1238", "The server's port");

int main(int argc, char** argv) {
  gflags::SetUsageMessage(
      "The SGX-Based Doubly Oblibvious RAM by Nankai University.");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);
  
  try {
    std::unique_ptr<Client> client = std::make_unique<Client>(FLAGS_address, FLAGS_port);
    client->init_enclave();
    std::string session_key;
    client->generate_session_key(session_key);
    client->init_sse();
    client->add_record(session_key, 0, "alice");
    client->add_record(session_key, 1, "bob");
    client->delete_record(session_key, 0, "alice");
    client->search_w(session_key, "bob");  
    LOG(plog::info) << "add success";
    client->destroy_enclave();
    client->close_connection();
  } catch (const std::exception& e) {
    LOG(plog::fatal) << e.what();
  }
  gflags::ShutDownCommandLineFlags();
  return 0;
}
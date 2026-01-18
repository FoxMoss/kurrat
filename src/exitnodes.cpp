
#include "helper.hpp"
#include "mbedtls/base64.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <curl/curl.h>
#include <curl/easy.h>
#include <exception>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

std::array<std::string, 9> consensus_hosts = {
    "128.31.0.39:9231",  "217.196.147.77:80", "45.66.35.11:80",
    "131.188.40.189:80", "193.23.244.244:80", "171.25.193.9:443",
    "199.58.81.140:80",  "204.13.164.118:80", "216.218.219.41:80"};

size_t write_data(void *buffer, size_t size, size_t nmemb,
                  std::stringstream *userp) {

  userp->write((char *)buffer, (size * nmemb));

  return size * nmemb;
}

int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                      curl_off_t ultotal, curl_off_t ulnow) {
  printf("\e[1A\e[K%li bytes read\n", dlnow);
  return 0;
}

std::optional<std::string> find_exit_node() {

  std::stringstream consensus_str;
  CURLcode code;
  std::string host;
  do {
    consensus_str.clear();
    host = consensus_hosts[rand() % consensus_hosts.size()];

    printf("reading consensus from host %s\n", host.c_str());

    auto handle = curl_easy_init();

    curl_easy_setopt(
        handle, CURLOPT_URL,
        ("http://" + host + "/tor/status-vote/current/consensus").c_str());

    curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, progress_callback);

    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &consensus_str);

    printf("0 bytes read\n");
    code = curl_easy_perform(handle);
    curl_easy_cleanup(handle);
  } while (code != CURLE_OK);

  std::string line;

  struct ExitInfo {
    std::string name;
    std::string idenity_key;
    std::string ip;
    std::string port;

    std::string ntor_key;
    size_t bandwidth_size;
  };

  std::vector<ExitInfo> exit_canidates;

  std::string name;
  std::string idenity_key;
  std::string ip;
  std::string port;
  size_t bandwidth_size;

  bool is_exit = false;
  bool is_fast = false;
  bool is_stable = false;
  bool is_running = false;
  bool is_valid = false;

  while (std::getline(consensus_str, line)) {
    if (line.size() < 5) {
      continue;
    }

    line.push_back(' ');

    std::string segement;
    std::string first_segment;
    size_t index = 0;
    for (auto c : line) {

      if (c == ' ' || c == 0) {

        if (first_segment == "r") {
          if (index == 1) {
            name = segement;
          } else if (index == 2) {
            idenity_key = segement;
          } else if (index == 6) {
            ip = segement;
          } else if (index == 7) {
            port = segement;
          }
        } else if (first_segment == "w") {
          if (index == 1) {
            sscanf(segement.c_str(), "Bandwidth=%zu", &bandwidth_size);
          }
        } else if (first_segment == "s" && segement != "") {
          if (segement == "Exit") {
            is_exit = true;
          } else if (segement == "Fast") {
            is_fast = true;
          } else if (segement == "Stable") {
            is_stable = true;
          } else if (segement == "Running") {
            is_running = true;
          } else if (segement == "Valid") {
            is_valid = true;
          }
        }

        if (index == 0) {
          first_segment = segement;
          if (first_segment == "s") {
            is_exit = false;
            is_fast = false;
            is_stable = false;
            is_running = false;
            is_valid = false;
          }
        }
        segement.clear();
        index++;
        continue;
      }
      segement.push_back(c);
    }

    if (first_segment == "p" && is_stable && is_running && is_fast && is_exit &&
        is_valid) {
      exit_canidates.push_back({.name = name,
                                .idenity_key = idenity_key,
                                .ip = ip,
                                .port = port,
                                .bandwidth_size = bandwidth_size});
    }
  }

  srand(0);
  std::sort(exit_canidates.begin(), exit_canidates.end(),
            [](ExitInfo &a, ExitInfo &b) {
              return a.bandwidth_size > b.bandwidth_size + rand() % 1000;
            });

  std::stringstream exit_data_str;
  for (auto exit : exit_canidates) {
    printf("%s:%s\n", exit.ip.c_str(), exit.port.c_str());

    if (exit.idenity_key.size() != 27) {
      continue;
    }

    std::string identity_paddeded = exit.idenity_key;

    add_padding_b64(identity_paddeded);

    std::vector<uint8_t> remote_identity_digest;
    remote_identity_digest.insert(remote_identity_digest.end(), 20, 0);

    size_t remote_identity_len;

    mbedtls_base64_decode((unsigned char *)remote_identity_digest.data(), 20,
                          &remote_identity_len,
                          (const unsigned char *)identity_paddeded.c_str(),
                          identity_paddeded.size());
    if (remote_identity_len != 20) {
      continue;
    }

    char identity_hex[20 * 2 + 1];
    snprintf(identity_hex, 20 * 2 + 1,
             "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%"
             "02X%02X%02X%02X",
             remote_identity_digest[0], remote_identity_digest[1],
             remote_identity_digest[2], remote_identity_digest[3],
             remote_identity_digest[4], remote_identity_digest[5],
             remote_identity_digest[6], remote_identity_digest[7],
             remote_identity_digest[8], remote_identity_digest[9],
             remote_identity_digest[10], remote_identity_digest[11],
             remote_identity_digest[12], remote_identity_digest[13],
             remote_identity_digest[14], remote_identity_digest[15],
             remote_identity_digest[16], remote_identity_digest[17],
             remote_identity_digest[18], remote_identity_digest[19]);

    printf("%s\n", identity_hex);

    auto handle = curl_easy_init();

    curl_easy_setopt(
        handle, CURLOPT_URL,
        ("http://" + host + "/tor/server/fp/" + std::string(identity_hex))
            .c_str());

    curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, progress_callback);

    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &exit_data_str);

    printf("0 bytes read\n");
    code = curl_easy_perform(handle);
    curl_easy_cleanup(handle);

    return {};
  }

  return {};
}

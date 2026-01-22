
#include "exitnodes.hpp"
#include "mbedtls/base64.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <curl/curl.h>
#include <curl/easy.h>
#include <exception>
#include <map>
#include <maxminddb.h>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

std::vector<std::string> consensus_hosts = {
    "128.31.0.39:9231",  "217.196.147.77:80", "45.66.35.11:80",
    "131.188.40.189:80", "193.23.244.244:80", "171.25.193.9:443",
    "199.58.81.140:80",  "204.13.164.118:80", "216.218.219.41:80",

};

size_t write_data(void *buffer, size_t size, size_t nmemb,
                  std::stringstream *userp) {

  userp->write((char *)buffer, (size * nmemb));

  return size * nmemb;
}

int progress_callback(time_t *clientp, curl_off_t dltotal, curl_off_t dlnow,
                      curl_off_t ultotal, curl_off_t ulnow) {
  if (time(NULL) - *clientp > 1 && dlnow == 0) {
    printf("connection timed out\n");
    return -1;
  }
  printf("\e[1A\e[K%li bytes read\n", dlnow);
  return 0;
}

std::optional<std::pair<std::vector<ExitInfo>, std::string>>
grab_consensus(std::optional<MMDB_s> mmdb, std::optional<std::string> place) {

  std::stringstream consensus_str;
  CURLcode code;
  std::string host;
  srand(time(NULL));

  std::shuffle(consensus_hosts.begin(), consensus_hosts.end(),
               std::default_random_engine(time(NULL)));

  consensus_hosts.insert(consensus_hosts.begin(), "0.0.0.0:9030");

  for (auto query_host : consensus_hosts) {
    consensus_str.clear();

    host = query_host;
    printf("reading consensus from host %s\n", host.c_str());

    auto handle = curl_easy_init();

    curl_easy_setopt(
        handle, CURLOPT_URL,
        ("http://" + host + "/tor/status-vote/current/consensus").c_str());

    curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, progress_callback);

    auto time_started = time(NULL);
    curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &time_started);

    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &consensus_str);

    printf("0 bytes read\n");
    code = curl_easy_perform(handle);
    curl_easy_cleanup(handle);

    if (code == CURLE_OK) {
      break;
    }
  }

  std::string line;

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

  std::sort(exit_canidates.begin(), exit_canidates.end(),
            [](ExitInfo &a, ExitInfo &b) {
              return a.bandwidth_size > b.bandwidth_size;
            });

  return std::make_pair(exit_canidates, host);
}
std::optional<ExitInfo> find_exit_node(std::optional<MMDB_s> mmdb,
                                       std::optional<std::string> place,
                                       std::string host,
                                       std::vector<ExitInfo> exit_canidates,
                                       const size_t restart_index_c) {

  // ranking exit node code
  // std::map<std::string, size_t> country_popularity;
  std::stringstream exit_data_str;

  size_t restart_index = restart_index_c;

  if (restart_index >= exit_canidates.size()) {
    restart_index = 0;
  }

  for (auto &exit : exit_canidates) {
    // if (rand() % 10 != 0 && !place.has_value()) // dont always use the same
    // exit
    //   continue;
    if (restart_index > 0) {
      restart_index--;
      continue;
    }

    if (mmdb.has_value()) {

      int gai_error, mmdb_error;
      MMDB_lookup_result_s result = MMDB_lookup_string(
          &mmdb.value(), exit.ip.c_str(), &gai_error, &mmdb_error);

      if (MMDB_SUCCESS != mmdb_error || 0 != gai_error || !result.found_entry) {
        printf("couldnt geolocate exit node %s\n", exit.ip.c_str());
        continue;
      }

      MMDB_entry_data_s entry_data;
      int status = MMDB_get_value(&result.entry, &entry_data, "country",
                                  "names", "en", NULL);
      if (status != MMDB_SUCCESS || !entry_data.has_data) {
        printf("couldnt match exit node to place %s\n", exit.ip.c_str());
        continue;
      }

      std::string place_name;
      place_name.insert(place_name.end(), entry_data.utf8_string,
                        entry_data.utf8_string + entry_data.data_size);
      // ranking exit node code
      // country_popularity[place_name]++;
      // continue;

      if (place.has_value() && place != place_name) {
        continue;
      }

      printf("trying %s:%s from %s\n", exit.ip.c_str(), exit.port.c_str(),
             place_name.c_str());

    } else {

      printf("trying %s:%s\n", exit.ip.c_str(), exit.port.c_str());
    }

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

    auto handle = curl_easy_init();

    auto exit_data_url =
        "http://" + host + "/tor/server/fp/" + std::string(identity_hex);
    curl_easy_setopt(handle, CURLOPT_URL, exit_data_url.c_str());

    printf("requesting data from %s\n", exit_data_url.c_str());

    curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);

    auto time_started = time(NULL);
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &time_started);

    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &exit_data_str);

    printf("0 bytes read\n");
    CURLcode code = curl_easy_perform(handle);
    curl_easy_cleanup(handle);

    if (code != CURLE_OK) {
      continue;
    }

    std::string line;
    while (std::getline(exit_data_str, line)) {
      if (line.size() < 5) {
        continue;
      }

      line.push_back(' ');

      std::string segement;
      std::string first_segment;
      size_t index = 0;
      for (auto c : line) {
        if (c == ' ' || c == 0) {

          if (first_segment == "ntor-onion-key" && index == 1) {
            exit.ntor_key = segement;
            return exit;
          }

          if (index == 0) {
            first_segment = segement;
          }
          segement.clear();
          index++;
          continue;
        }
        segement.push_back(c);
      }
    }
  }

  // Ranking exit node code
  // std::vector<std::pair<std::string, size_t>> sorted_map;
  //
  // for (auto country : country_popularity) {
  //   sorted_map.push_back(country);
  // }
  //
  // std::sort(
  //     sorted_map.begin(), sorted_map.end(),
  //     [](std::pair<std::string, size_t> &a, std::pair<std::string, size_t>
  //     &b) {
  //       return a.second > b.second;
  //     });
  //
  // printf("\n\nCountries of exit nodes ranked:\n");
  // for (auto country : sorted_map) {
  //   printf("%s: %zu\n", country.first.c_str(), country.second);
  // }

  return {};
}

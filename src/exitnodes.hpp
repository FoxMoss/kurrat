#pragma once
#include <maxminddb.h>
#include <optional>
#include <string>

struct ExitInfo {
  std::string name;
  std::string idenity_key;
  std::string ip;
  std::string port;

  size_t bandwidth_size;

  std::string ntor_key;
};

void add_padding_b64(std::string &b64);

std::optional<ExitInfo> find_exit_node(std::optional<MMDB_s> mmdb,
                                       std::optional<std::string> place);

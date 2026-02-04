#pragma once

#include <string>
#include <vector>

// High-level compression interface
std::vector<unsigned char> compress_data(const std::string& input);
std::string decompress_data(const unsigned char* data, size_t len);

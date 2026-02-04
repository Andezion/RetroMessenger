#pragma once

#include <vector>
#include <cstddef>

// tANS compression for short messages
std::vector<unsigned char> tans_encode(const unsigned char* data, size_t len);
std::vector<unsigned char> tans_decode(const unsigned char* data, size_t len);

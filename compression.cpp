#include "compression.h"
#include "tans_compression.h"
#include <zstd.h>
#include <cstring>

static const size_t COMPRESS_THRESHOLD = 64;
static const size_t TANS_THRESHOLD = 256;

static std::vector<unsigned char> zstd_compress(const unsigned char* data, size_t len) {
    size_t bound = ZSTD_compressBound(len);
    std::vector<unsigned char> out(bound);
    size_t compressed_size = ZSTD_compress(out.data(), bound, data, len, 3);
    if (ZSTD_isError(compressed_size)) return {};
    out.resize(compressed_size);
    return out;
}

static std::vector<unsigned char> zstd_decompress(const unsigned char* data, size_t len) {
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(data, len);
    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN || decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        decompressed_size = len * 10;
    }
    std::vector<unsigned char> out(decompressed_size);
    size_t result = ZSTD_decompress(out.data(), out.size(), data, len);
    if (ZSTD_isError(result)) return {};
    out.resize(result);
    return out;
}

std::vector<unsigned char> compress_data(const std::string& input) {
    if (input.size() < COMPRESS_THRESHOLD) {
        std::vector<unsigned char> out(1 + input.size());
        out[0] = 0x00;
        std::memcpy(out.data() + 1, input.data(), input.size());
        return out;
    }

    if (input.size() < TANS_THRESHOLD) {
        auto compressed = tans_encode(
            reinterpret_cast<const unsigned char*>(input.data()), input.size());
        if (!compressed.empty() && compressed.size() < input.size()) {
            std::vector<unsigned char> out(1 + compressed.size());
            out[0] = 0x02;
            std::memcpy(out.data() + 1, compressed.data(), compressed.size());
            return out;
        }
        std::vector<unsigned char> out(1 + input.size());
        out[0] = 0x00;
        std::memcpy(out.data() + 1, input.data(), input.size());
        return out;
    }

    auto compressed = zstd_compress(
        reinterpret_cast<const unsigned char*>(input.data()), input.size());
    if (!compressed.empty() && compressed.size() < input.size()) {
        std::vector<unsigned char> out(1 + compressed.size());
        out[0] = 0x01;
        std::memcpy(out.data() + 1, compressed.data(), compressed.size());
        return out;
    }
    std::vector<unsigned char> out(1 + input.size());
    out[0] = 0x00;
    std::memcpy(out.data() + 1, input.data(), input.size());
    return out;
}

std::string decompress_data(const unsigned char* data, size_t len) {
    if (len == 0) return "";
    if (data[0] == 0x00) {
        return std::string(reinterpret_cast<const char*>(data + 1), len - 1);
    }
    if (data[0] == 0x02) {
        auto decoded = tans_decode(data + 1, len - 1);
        if (decoded.empty()) return "[tANS decompression error]";
        return std::string(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    }
    if (data[0] == 0x01) {
        auto decoded = zstd_decompress(data + 1, len - 1);
        if (decoded.empty()) return "[decompression error]";
        return std::string(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    }
    return "[unknown compression format]";
}

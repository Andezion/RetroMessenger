#include "tans_compression.h"
#include <algorithm>
#include <cstring>
#include <cstdint>

static const size_t TANS_TABLE_LOG = 11;
static const size_t TANS_TABLE_SIZE = 1u << TANS_TABLE_LOG;

struct TANSEncodeSymbol {
    int16_t delta_find_state;
    uint16_t delta_nb_bits;
};

struct TANSDecodeEntry {
    uint8_t symbol;
    uint8_t nb_bits;
    uint16_t new_state;
};

static TANSDecodeEntry g_tans_decode_table[TANS_TABLE_SIZE];
static std::vector<TANSEncodeSymbol> g_tans_encode_table[256];

static void tans_normalize_freq(const unsigned char* data, size_t len, uint16_t norm[256]) {
    uint32_t count[256] = {};
    for (size_t i = 0; i < len; i++) count[data[i]]++;

    int n_symbols = 0;
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) n_symbols++;
    }
    if (n_symbols == 0) {
        std::memset(norm, 0, sizeof(uint16_t) * 256);
        return;
    }

    std::memset(norm, 0, sizeof(uint16_t) * 256);

    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            norm[i] = std::max<uint16_t>(1, (uint16_t)((uint64_t)count[i] * TANS_TABLE_SIZE / len));
        }
    }

    size_t sum = 0;
    for (int i = 0; i < 256; i++) sum += norm[i];

    while (sum > TANS_TABLE_SIZE) {
        int best = -1;
        for (int i = 0; i < 256; i++) {
            if (norm[i] > 1 && (best < 0 || norm[i] > norm[best])) best = i;
        }
        if (best < 0) break;
        norm[best]--;
        sum--;
    }
    while (sum < TANS_TABLE_SIZE) {
        int best = -1;
        double best_ratio = 1e30;
        for (int i = 0; i < 256; i++) {
            if (count[i] > 0) {
                double ratio = (double)norm[i] / count[i];
                if (ratio < best_ratio) {
                    best_ratio = ratio;
                    best = i;
                }
            }
        }
        if (best < 0) break;
        norm[best]++;
        sum++;
    }
}

static void tans_build_tables(const uint16_t norm[256]) {
    uint8_t symbol_table[TANS_TABLE_SIZE];
    size_t pos = 0;
    size_t step = (TANS_TABLE_SIZE >> 1) + (TANS_TABLE_SIZE >> 3) + 3;
    size_t mask = TANS_TABLE_SIZE - 1;

    uint16_t cumul[257];
    cumul[0] = 0;
    for (int i = 0; i < 256; i++) cumul[i + 1] = cumul[i] + norm[i];

    for (int s = 0; s < 256; s++) {
        for (uint16_t j = 0; j < norm[s]; j++) {
            symbol_table[pos] = (uint8_t)s;
            pos = (pos + step) & mask;
            while (pos >= TANS_TABLE_SIZE) pos = (pos + step) & mask;
        }
    }

    uint16_t next_state[256];
    for (int s = 0; s < 256; s++) next_state[s] = norm[s];

    for (size_t i = 0; i < TANS_TABLE_SIZE; i++) {
        uint8_t sym = symbol_table[i];
        uint16_t ns = next_state[sym]++;

        int nb_bits = 0;
        uint16_t temp = ns;
        while (temp < TANS_TABLE_SIZE) { temp <<= 1; nb_bits++; }

        g_tans_decode_table[i].symbol = sym;
        g_tans_decode_table[i].nb_bits = (uint8_t)nb_bits;
        g_tans_decode_table[i].new_state = (uint16_t)((ns << nb_bits) - TANS_TABLE_SIZE);
    }

    for (int s = 0; s < 256; s++) {
        g_tans_encode_table[s].clear();
        if (norm[s] == 0) continue;
        g_tans_encode_table[s].resize(norm[s]);
    }

    uint16_t sym_count[256] = {};
    for (size_t i = 0; i < TANS_TABLE_SIZE; i++) {
        uint8_t sym = g_tans_decode_table[i].symbol;
        uint8_t nb = g_tans_decode_table[i].nb_bits;

        size_t idx = sym_count[sym]++;
        if (idx < g_tans_encode_table[sym].size()) {
            g_tans_encode_table[sym][idx].delta_find_state = (int16_t)i;
            g_tans_encode_table[sym][idx].delta_nb_bits = nb;
        }
    }
}

std::vector<unsigned char> tans_encode(const unsigned char* data, size_t len) {
    if (len == 0 || len > 65535) return {};

    uint16_t norm[256];
    tans_normalize_freq(data, len, norm);

    int n_symbols = 0;
    for (int i = 0; i < 256; i++) {
        if (norm[i] > 0) n_symbols++;
    }
    if (n_symbols <= 1) {
        return {};
    }

    tans_build_tables(norm);

    uint32_t state = TANS_TABLE_SIZE;

    std::vector<unsigned char> bits_buf;
    bits_buf.reserve(len);
    uint64_t bit_buffer = 0;
    int bit_count = 0;

    auto flush_bits = [&]() {
        while (bit_count >= 8) {
            bit_count -= 8;
            bits_buf.push_back((unsigned char)((bit_buffer >> bit_count) & 0xFF));
        }
    };

    for (size_t i = 0; i < len; i++) {
        uint8_t sym = data[i];
        if (norm[sym] == 0) return {};

        uint16_t freq = norm[sym];

        uint32_t s = state;
        while (s >= (uint32_t)(freq << (TANS_TABLE_LOG + 1))) {
            bit_buffer = (bit_buffer << 1) | (s & 1);
            bit_count++;
            s >>= 1;
            flush_bits();
        }

        if (s < freq) {
            s = freq;
        }

        uint16_t sub_idx;
        if (s >= 2u * freq) {
            sub_idx = (uint16_t)(s % freq);
        } else {
            sub_idx = (uint16_t)(s - freq);
        }
        if (sub_idx >= g_tans_encode_table[sym].size()) {
            sub_idx = sub_idx % (uint16_t)g_tans_encode_table[sym].size();
        }

        state = TANS_TABLE_SIZE + g_tans_encode_table[sym][sub_idx].delta_find_state;
    }

    bit_buffer = (bit_buffer << TANS_TABLE_LOG) | (state - TANS_TABLE_SIZE);
    bit_count += TANS_TABLE_LOG;
    flush_bits();

    if (bit_count > 0) {
        bit_buffer <<= (8 - bit_count);
        bits_buf.push_back((unsigned char)((bit_buffer) & 0xFF));
    }

    std::vector<unsigned char> result;
    result.reserve(2 + 512 + bits_buf.size());

    result.push_back((unsigned char)((len >> 8) & 0xFF));
    result.push_back((unsigned char)(len & 0xFF));

    result.push_back((unsigned char)n_symbols);
    for (int i = 0; i < 256; i++) {
        if (norm[i] > 0) {
            result.push_back((unsigned char)i);
            result.push_back((unsigned char)((norm[i] >> 8) & 0xFF));
            result.push_back((unsigned char)(norm[i] & 0xFF));
        }
    }

    result.insert(result.end(), bits_buf.begin(), bits_buf.end());

    return result;
}

std::vector<unsigned char> tans_decode(const unsigned char* data, size_t len) {
    if (len < 3) return {};

    size_t orig_len = ((size_t)data[0] << 8) | data[1];
    size_t offset = 2;

    if (offset >= len) return {};
    int n_symbols = data[offset++];

    uint16_t norm[256] = {};
    for (int i = 0; i < n_symbols; i++) {
        if (offset + 3 > len) return {};
        uint8_t sym = data[offset++];
        norm[sym] = ((uint16_t)data[offset] << 8) | data[offset + 1];
        offset += 2;
    }

    tans_build_tables(norm);

    const unsigned char* bits_data = data + offset;
    size_t bits_len = len - offset;

    size_t bit_pos = 0;
    auto read_bits = [&](int n) -> uint32_t {
        uint32_t val = 0;
        for (int i = 0; i < n; i++) {
            size_t byte_idx = bit_pos / 8;
            int bit_idx = 7 - (bit_pos % 8);
            if (byte_idx < bits_len) {
                val = (val << 1) | ((bits_data[byte_idx] >> bit_idx) & 1);
            }
            bit_pos++;
        }
        return val;
    };

    uint32_t state = read_bits(TANS_TABLE_LOG);
    state += TANS_TABLE_SIZE;

    std::vector<unsigned char> output;
    output.reserve(orig_len);

    for (size_t i = 0; i < orig_len; i++) {
        uint16_t table_idx = (uint16_t)(state - TANS_TABLE_SIZE);
        if (table_idx >= TANS_TABLE_SIZE) break;

        output.push_back(g_tans_decode_table[table_idx].symbol);
        uint8_t nb = g_tans_decode_table[table_idx].nb_bits;
        uint16_t new_state_base = g_tans_decode_table[table_idx].new_state;

        uint32_t bits_read = read_bits(nb);
        state = TANS_TABLE_SIZE + new_state_base + bits_read;
    }

    return output;
}

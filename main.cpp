#include <wx/wx.h>
#include <wx/listbox.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <thread>
#include <memory>

#include <map>
#include <deque>
#include <mutex>
#include <sodium.h>
#include <zstd.h>
#include <vector>
#include <cstring>
#include <algorithm>

using boost::asio::ip::tcp;

wxDECLARE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);

static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::string out(len * 2, '\0');
    sodium_bin2hex(&out[0], out.size() + 1, data, len);
    return out;
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> out(hex.size() / 2);
    size_t bin_len = 0;
    sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(),
                   nullptr, &bin_len, nullptr);
    out.resize(bin_len);
    return out;
}

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

static const size_t TANS_TABLE_LOG = 11;
static const size_t TANS_TABLE_SIZE = 1u << TANS_TABLE_LOG; 
static uint16_t g_tans_norm_freq[256];
static bool g_tans_tables_built = false;

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

    size_t remaining = TANS_TABLE_SIZE;
    size_t total = len;
    std::memset(norm, 0, sizeof(uint16_t) * 256);

    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            norm[i] = std::max<uint16_t>(1, (uint16_t)((uint64_t)count[i] * TANS_TABLE_SIZE / total));
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

        int nb_bits = TANS_TABLE_LOG;
        uint16_t temp = ns;
        while (temp >= TANS_TABLE_SIZE) { temp >>= 1; nb_bits--; } 
        
        nb_bits = 0;
        temp = ns;
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
        uint16_t ns = g_tans_decode_table[i].new_state;

        size_t idx = sym_count[sym]++;
        if (idx < g_tans_encode_table[sym].size()) {
            g_tans_encode_table[sym][idx].delta_find_state = (int16_t)i;
            g_tans_encode_table[sym][idx].delta_nb_bits = nb;
        }
    }

    g_tans_tables_built = true;
}

static std::vector<unsigned char> tans_encode(const unsigned char* data, size_t len) {
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

        int nb_bits = 0;
        uint32_t s = state;
        while (s >= (uint32_t)(freq << (TANS_TABLE_LOG + 1))) {
            bit_buffer = (bit_buffer << 1) | (s & 1);
            bit_count++;
            s >>= 1;
            nb_bits++;
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

static std::vector<unsigned char> tans_decode(const unsigned char* data, size_t len) {
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

static std::vector<unsigned char> compress_data(const std::string& input) {
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

static std::string decompress_data(const unsigned char* data, size_t len) {
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

static const size_t PAD_BLOCK_SIZE = 256;

static std::vector<unsigned char> pad_data(const std::vector<unsigned char>& input) {
    size_t padded_len = ((input.size() / PAD_BLOCK_SIZE) + 1) * PAD_BLOCK_SIZE;
    std::vector<unsigned char> out(padded_len);
    std::memcpy(out.data(), input.data(), input.size());
    out[input.size()] = 0x80;
    for (size_t i = input.size() + 1; i < padded_len; ++i) {
        out[i] = 0x00;
    }
    return out;
}

static std::vector<unsigned char> unpad_data(const std::vector<unsigned char>& input) {
    if (input.empty()) return {};
    size_t i = input.size();
    while (i > 0) {
        --i;
        if (input[i] == 0x80) {
            return std::vector<unsigned char>(input.begin(), input.begin() + i);
        }
        if (input[i] != 0x00) {
            return input;
        }
    }
    return input;
}

static void kdf_derive_pair(
    const unsigned char* input_key, size_t input_len,
    const unsigned char* salt, size_t salt_len,
    const char* context,
    unsigned char out_key1[32],
    unsigned char out_key2[32])
{
    crypto_generichash_state state;

    crypto_generichash_init(&state, input_key, input_len, 32);
    if (salt && salt_len > 0)
        crypto_generichash_update(&state, salt, salt_len);
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(context), strlen(context));
    unsigned char tag = 0x01;
    crypto_generichash_update(&state, &tag, 1);
    crypto_generichash_final(&state, out_key1, 32);

    crypto_generichash_init(&state, input_key, input_len, 32);
    if (salt && salt_len > 0)
        crypto_generichash_update(&state, salt, salt_len);
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(context), strlen(context));
    tag = 0x02;
    crypto_generichash_update(&state, &tag, 1);
    crypto_generichash_final(&state, out_key2, 32);

    sodium_memzero(&state, sizeof(state));
}

static void chain_advance(
    const unsigned char chain_key_in[32],
    unsigned char message_key_out[32],
    unsigned char chain_key_out[32])
{
    kdf_derive_pair(chain_key_in, 32, nullptr, 0, "chain",
                    message_key_out, chain_key_out);
}

static void dh_ratchet_step(
    const unsigned char root_key_in[32],
    const unsigned char* dh_output, size_t dh_len,
    unsigned char root_key_out[32],
    unsigned char chain_key_out[32])
{
    kdf_derive_pair(root_key_in, 32, dh_output, dh_len, "ratchet",
                    root_key_out, chain_key_out);
}

static void compute_message_hash(
    const unsigned char* prev_hash,
    const unsigned char* ciphertext, size_t ciphertext_len,
    uint32_t counter,
    unsigned char out_hash[32])
{
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, 32);
    crypto_generichash_update(&state, prev_hash, 32);
    crypto_generichash_update(&state, ciphertext, ciphertext_len);
    unsigned char counter_bytes[4] = {
        (unsigned char)((counter >> 24) & 0xFF),
        (unsigned char)((counter >> 16) & 0xFF),
        (unsigned char)((counter >> 8) & 0xFF),
        (unsigned char)(counter & 0xFF)
    };
    crypto_generichash_update(&state, counter_bytes, 4);
    crypto_generichash_final(&state, out_hash, 32);
}

struct RatchetState {
    unsigned char root_key[32];
    unsigned char send_chain_key[32];
    unsigned char recv_chain_key[32];

    unsigned char my_eph_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char my_eph_sk[crypto_box_SECRETKEYBYTES];
    unsigned char peer_eph_pk[crypto_box_PUBLICKEYBYTES];

    uint32_t send_counter;
    uint32_t recv_counter;

    unsigned char last_sent_hash[32];
    unsigned char last_recv_hash[32];

    bool needs_dh_ratchet;
    bool peer_eph_known; 

    void zero() {
        sodium_memzero(root_key, sizeof(root_key));
        sodium_memzero(send_chain_key, sizeof(send_chain_key));
        sodium_memzero(recv_chain_key, sizeof(recv_chain_key));
        sodium_memzero(my_eph_sk, sizeof(my_eph_sk));
        send_counter = 0;
        recv_counter = 0;
    }
};

static void init_ratchet(
    RatchetState& ratchet,
    const unsigned char initial_shared_key[crypto_box_BEFORENMBYTES],
    bool is_initiator)
{
    unsigned char dummy[32];
    kdf_derive_pair(initial_shared_key, crypto_box_BEFORENMBYTES,
                    nullptr, 0, "init", ratchet.root_key, dummy);
    sodium_memzero(dummy, 32);

    crypto_box_keypair(ratchet.my_eph_pk, ratchet.my_eph_sk);

    std::memset(ratchet.peer_eph_pk, 0, sizeof(ratchet.peer_eph_pk));
    ratchet.peer_eph_known = false;

    unsigned char ck1[32], ck2[32];
    kdf_derive_pair(ratchet.root_key, 32, nullptr, 0, "initial_chains", ck1, ck2);

    if (is_initiator) {
        std::memcpy(ratchet.send_chain_key, ck1, 32);
        std::memcpy(ratchet.recv_chain_key, ck2, 32);
    } else {
        std::memcpy(ratchet.send_chain_key, ck2, 32);
        std::memcpy(ratchet.recv_chain_key, ck1, 32);
    }

    sodium_memzero(ck1, 32);
    sodium_memzero(ck2, 32);

    ratchet.send_counter = 0;
    ratchet.recv_counter = 0;
    std::memset(ratchet.last_sent_hash, 0, 32);
    std::memset(ratchet.last_recv_hash, 0, 32);
    ratchet.needs_dh_ratchet = is_initiator;
}

static const uint8_t MSG_TYPE_DATA = 0x01;

static const size_t RATCHET_HEADER_SIZE = 93;

static std::vector<unsigned char> seal_message_ratchet(
    const std::string& message,
    RatchetState& ratchet)
{
    if (ratchet.needs_dh_ratchet && ratchet.peer_eph_known) {
        unsigned char dh_output[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(dh_output, ratchet.my_eph_sk, ratchet.peer_eph_pk) == 0) {
            unsigned char new_root[32], new_chain[32];
            dh_ratchet_step(ratchet.root_key, dh_output, sizeof(dh_output),
                            new_root, new_chain);
            std::memcpy(ratchet.root_key, new_root, 32);
            std::memcpy(ratchet.send_chain_key, new_chain, 32);

            sodium_memzero(dh_output, sizeof(dh_output));
            sodium_memzero(new_root, 32);
            sodium_memzero(new_chain, 32);
        }
        crypto_box_keypair(ratchet.my_eph_pk, ratchet.my_eph_sk);
        ratchet.needs_dh_ratchet = false;
    }

    unsigned char message_key[32];
    unsigned char new_chain_key[32];
    chain_advance(ratchet.send_chain_key, message_key, new_chain_key);
    std::memcpy(ratchet.send_chain_key, new_chain_key, 32);
    sodium_memzero(new_chain_key, 32);

    auto compressed = compress_data(message);
    auto padded = pad_data(compressed);

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; 
    randombytes_buf(nonce, sizeof(nonce));

    uint32_t counter = ratchet.send_counter;
    unsigned char counter_bytes[4] = {
        (unsigned char)((counter >> 24) & 0xFF),
        (unsigned char)((counter >> 16) & 0xFF),
        (unsigned char)((counter >> 8) & 0xFF),
        (unsigned char)(counter & 0xFF)
    };

    std::vector<unsigned char> ad;
    ad.insert(ad.end(), ratchet.my_eph_pk, ratchet.my_eph_pk + 32);
    ad.insert(ad.end(), ratchet.last_sent_hash, ratchet.last_sent_hash + 32);
    ad.insert(ad.end(), counter_bytes, counter_bytes + 4);

    std::vector<unsigned char> ciphertext(
        padded.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        padded.data(), padded.size(),
        ad.data(), ad.size(),
        nullptr, nonce, message_key);
    ciphertext.resize((size_t)ciphertext_len);

    std::vector<unsigned char> wire;
    wire.reserve(RATCHET_HEADER_SIZE + ciphertext.size());
    wire.push_back(MSG_TYPE_DATA);
    wire.insert(wire.end(), ratchet.my_eph_pk, ratchet.my_eph_pk + 32);
    wire.insert(wire.end(), ratchet.last_sent_hash, ratchet.last_sent_hash + 32);
    wire.insert(wire.end(), counter_bytes, counter_bytes + 4);
    wire.insert(wire.end(), nonce, nonce + 24);
    wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

    compute_message_hash(ratchet.last_sent_hash, ciphertext.data(),
                         ciphertext.size(), counter, ratchet.last_sent_hash);

    ratchet.send_counter++;
    sodium_memzero(message_key, sizeof(message_key));

    return wire;
}

static std::string unseal_message_ratchet(
    const unsigned char* data, size_t len,
    RatchetState& ratchet)
{
    if (len < RATCHET_HEADER_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return "[invalid message: too short]";
    }

    size_t offset = 0;
    uint8_t msg_type = data[offset++];
    if (msg_type != MSG_TYPE_DATA) {
        return "[unsupported message type]";
    }

    const unsigned char* peer_eph_pk = data + offset; offset += 32;
    const unsigned char* prev_hash   = data + offset; offset += 32;

    uint32_t counter = ((uint32_t)data[offset] << 24) |
                       ((uint32_t)data[offset+1] << 16) |
                       ((uint32_t)data[offset+2] << 8) |
                       (uint32_t)data[offset+3];
    offset += 4;

    const unsigned char* nonce = data + offset; offset += 24;
    const unsigned char* ciphertext = data + offset;
    size_t ciphertext_len = len - offset;

    if (!ratchet.peer_eph_known ||
        sodium_memcmp(peer_eph_pk, ratchet.peer_eph_pk, 32) != 0) {
        std::memcpy(ratchet.peer_eph_pk, peer_eph_pk, 32);
        ratchet.peer_eph_known = true;

        unsigned char dh_output[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(dh_output, ratchet.my_eph_sk, ratchet.peer_eph_pk) == 0) {
            unsigned char new_root[32], new_chain[32];
            dh_ratchet_step(ratchet.root_key, dh_output, sizeof(dh_output),
                            new_root, new_chain);
            std::memcpy(ratchet.root_key, new_root, 32);
            std::memcpy(ratchet.recv_chain_key, new_chain, 32);

            sodium_memzero(dh_output, sizeof(dh_output));
            sodium_memzero(new_root, 32);
            sodium_memzero(new_chain, 32);
        }
        ratchet.needs_dh_ratchet = true;
    }

    unsigned char message_key[32];
    unsigned char new_chain_key[32];
    chain_advance(ratchet.recv_chain_key, message_key, new_chain_key);
    std::memcpy(ratchet.recv_chain_key, new_chain_key, 32);
    sodium_memzero(new_chain_key, 32);

    unsigned char counter_bytes[4] = {
        (unsigned char)((counter >> 24) & 0xFF),
        (unsigned char)((counter >> 16) & 0xFF),
        (unsigned char)((counter >> 8) & 0xFF),
        (unsigned char)(counter & 0xFF)
    };

    std::vector<unsigned char> ad;
    ad.insert(ad.end(), peer_eph_pk, peer_eph_pk + 32);
    ad.insert(ad.end(), prev_hash, prev_hash + 32);
    ad.insert(ad.end(), counter_bytes, counter_bytes + 4);

    std::vector<unsigned char> plaintext(
        ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext, ciphertext_len,
            ad.data(), ad.size(),
            nonce, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return "[decryption failed]";
    }
    plaintext.resize((size_t)plaintext_len);

    compute_message_hash(ratchet.last_recv_hash, ciphertext, ciphertext_len,
                         counter, ratchet.last_recv_hash);
    ratchet.recv_counter++;
    sodium_memzero(message_key, sizeof(message_key));

    auto unpadded = unpad_data(plaintext);
    return decompress_data(unpadded.data(), unpadded.size());
}

std::string generateUniqueID() {
    unsigned char buf[16];
    randombytes_buf(buf, sizeof(buf));
    return bytes_to_hex(buf, sizeof(buf));
}

std::string truncateID(const std::string& id) {
    if (id.size() <= 12) return id;
    return id.substr(0, 6) + ".." + id.substr(id.size() - 6);
}

struct ChatInfo {
    std::string chatID;
    std::string peerID;
    std::string localAlias;
    std::vector<std::pair<std::string, std::string>> messageCache;
    RatchetState ratchet;
    bool active;
    bool is_initiator;
};

struct ReceivedMessageData {
    std::string chat_id;
    std::vector<unsigned char> payload;
};

struct PeerConnectedData {
    std::string chat_id;
    std::string peer_id;
    RatchetState ratchet;
};

static std::vector<unsigned char> frame_encode(const std::vector<unsigned char>& payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> frame(4 + payload.size());
    frame[0] = (len >> 24) & 0xFF;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    std::memcpy(frame.data() + 4, payload.data(), payload.size());
    return frame;
}

static std::vector<unsigned char> frame_encode_string(const std::string& s) {
    std::vector<unsigned char> payload(s.begin(), s.end());
    return frame_encode(payload);
}

class P2PSession : public std::enable_shared_from_this<P2PSession> {
public:
    P2PSession(tcp::socket socket, wxEvtHandler* handler, const std::string& chatID)
        : socket_(std::move(socket)), event_handler_(handler), chat_id_(chatID)
    {
    }

    void start() {
        read_frame_header();
    }

    void send_raw(const std::vector<unsigned char>& framed_data) {
        auto self(shared_from_this());
        boost::asio::post(socket_.get_executor(), [this, self, framed_data]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(framed_data);
            if (!write_in_progress) {
                do_write();
            }
        });
    }

    std::string get_chat_id() const { return chat_id_; }

private:
    void read_frame_header() {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(header_buf_, 4),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                                   static_cast<uint32_t>(header_buf_[3]);

                    if (len > 10 * 1024 * 1024) {
                        notify_disconnect();
                        return;
                    }
                    payload_buf_.resize(len);
                    read_frame_payload(len);
                } else {
                    notify_disconnect();
                }
            });
    }

    void read_frame_payload(uint32_t len) {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(payload_buf_.data(), len),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    if (event_handler_) {
                        auto* msg_data = new ReceivedMessageData();
                        msg_data->chat_id = chat_id_;
                        msg_data->payload.assign(payload_buf_.begin(), payload_buf_.end());

                        wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                        event.SetClientData(msg_data);
                        wxQueueEvent(event_handler_, event.Clone());
                    }
                    read_frame_header();
                } else {
                    notify_disconnect();
                }
            });
    }

    void do_write() {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
            boost::asio::buffer(write_queue_.front()),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    write_queue_.pop_front();
                    if (!write_queue_.empty()) {
                        do_write();
                    }
                } else {
                    notify_disconnect();
                }
            });
    }

    void notify_disconnect() {
        if (event_handler_) {
            wxCommandEvent event(wxEVT_PEER_DISCONNECTED);
            event.SetClientData(new std::string(chat_id_));
            wxQueueEvent(event_handler_, event.Clone());
        }
    }

    tcp::socket socket_;
    wxEvtHandler* event_handler_;
    std::string chat_id_;
    unsigned char header_buf_[4];
    std::vector<unsigned char> payload_buf_;
    std::deque<std::vector<unsigned char>> write_queue_;
};

class P2PManager {
public:
    P2PManager(wxEvtHandler* handler,
               const unsigned char* my_pk, const unsigned char* my_sk,
               unsigned short port = 0)
        : event_handler_(handler),
          acceptor_(io_context_),
          listening_port_(port)
    {
        std::memcpy(my_pk_, my_pk, crypto_box_PUBLICKEYBYTES);
        std::memcpy(my_sk_, my_sk, crypto_box_SECRETKEYBYTES);

        if (port == 0) {
            listening_port_ = find_available_port();
        }

        tcp::endpoint endpoint(tcp::v4(), listening_port_);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();

        start_accept();
        io_thread_ = std::thread([this]() { io_context_.run(); });
    }

    ~P2PManager() {
        io_context_.stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

    unsigned short get_listening_port() const { return listening_port_; }

    void send_invitation(const std::string& peer_address, const std::string& peer_port,
                         const std::string& my_id) {
        auto socket = std::make_shared<tcp::socket>(io_context_);

        try {
            tcp::resolver resolver(io_context_);
            auto endpoints = resolver.resolve(peer_address, peer_port);
            boost::asio::connect(*socket, endpoints);

            socket->non_blocking(false);

            std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
            std::string invite_msg = "INVITE:" + pk_hex + ":" + my_id + "\n";
            boost::asio::write(*socket, boost::asio::buffer(invite_msg));

            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(socket->native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            boost::asio::streambuf buffer;
            boost::asio::read_until(*socket, buffer, '\n');
            std::istream is(&buffer);
            std::string response;
            std::getline(is, response);

            if (response.substr(0, 6) == "ACCEPT") {
                size_t pos1 = response.find(':', 7);
                std::string peer_pk_hex = response.substr(7, pos1 - 7);
                std::string peer_id = response.substr(pos1 + 1);

                auto peer_pk = hex_to_bytes(peer_pk_hex);
                if (peer_pk.size() != crypto_box_PUBLICKEYBYTES) {
                    wxLogError("Invalid peer public key size");
                    return;
                }

                unsigned char shared_key[crypto_box_BEFORENMBYTES];
                if (crypto_box_beforenm(shared_key, peer_pk.data(), my_sk_) != 0) {
                    wxLogError("Failed to compute shared key");
                    return;
                }

                std::string chat_id = generateUniqueID();

                auto* conn_data = new PeerConnectedData();
                conn_data->chat_id = chat_id;
                conn_data->peer_id = peer_id;
                init_ratchet(conn_data->ratchet, shared_key, true);
                sodium_memzero(shared_key, sizeof(shared_key));

                auto session = std::make_shared<P2PSession>(std::move(*socket), event_handler_, chat_id);
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex_);
                    sessions_[chat_id] = session;
                }
                session->start();

                wxCommandEvent event(wxEVT_PEER_CONNECTED);
                event.SetClientData(conn_data);
                wxQueueEvent(event_handler_, event.Clone());
            }
        } catch (const std::exception& e) {
            wxLogError("Failed to send invitation: %s", e.what());
        }
    }

    void send_raw(const std::string& chat_id, const std::vector<unsigned char>& framed_data) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(chat_id);
        if (it != sessions_.end()) {
            it->second->send_raw(framed_data);
        }
    }

    void add_session(const std::string& chat_id, std::shared_ptr<P2PSession> session) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[chat_id] = session;
    }

    void close_chat(const std::string& chat_id) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.erase(chat_id);
    }

    int store_pending_socket(tcp::socket socket) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        int id = next_pending_id_++;
        pending_sockets_.emplace(id, std::move(socket));
        return id;
    }

    tcp::socket take_pending_socket(int id) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_sockets_.find(id);
        if (it != pending_sockets_.end()) {
            tcp::socket s = std::move(it->second);
            pending_sockets_.erase(it);
            return s;
        }
        throw std::runtime_error("Pending socket not found");
    }

private:
    unsigned short find_available_port() {
        tcp::acceptor acc(io_context_, tcp::endpoint(tcp::v4(), 0));
        unsigned short port = acc.local_endpoint().port();
        acc.close();
        return port;
    }

    void start_accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket,
            [this, socket](const boost::system::error_code& ec) {
                if (!ec) {
                    handle_new_connection(std::move(*socket));
                }
                do_accept();
            });
    }

    void handle_new_connection(tcp::socket socket) {
        try {
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            boost::asio::streambuf buffer;
            boost::asio::read_until(socket, buffer, '\n');
            std::istream is(&buffer);
            std::string invite_msg;
            std::getline(is, invite_msg);

            if (invite_msg.substr(0, 6) == "INVITE") {
                size_t pos1 = invite_msg.find(':', 7);
                std::string peer_pk_hex = invite_msg.substr(7, pos1 - 7);
                std::string peer_id = invite_msg.substr(pos1 + 1);

                int pending_id = store_pending_socket(std::move(socket));

                wxCommandEvent event(wxEVT_INVITATION_RECEIVED);
                event.SetString(wxString::Format("%s;%s;%d", peer_id, peer_pk_hex, pending_id));
                wxQueueEvent(event_handler_, event.Clone());
            }
        } catch (const std::exception& e) {
            wxLogError("Error handling connection: %s", e.what());
        }
    }

    void do_accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket,
            [this, socket](const boost::system::error_code& ec) {
                if (!ec) {
                    handle_new_connection(std::move(*socket));
                }
                do_accept();
            });
    }

    wxEvtHandler* event_handler_;
    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    unsigned short listening_port_;
    std::thread io_thread_;

    unsigned char my_pk_[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk_[crypto_box_SECRETKEYBYTES];

    std::map<std::string, std::shared_ptr<P2PSession>> sessions_;
    std::mutex sessions_mutex_;

    std::map<int, tcp::socket> pending_sockets_;
    std::mutex pending_mutex_;
    int next_pending_id_ = 0;
};

class NewChatDialog : public wxDialog {
public:
    NewChatDialog(wxWindow* parent)
        : wxDialog(parent, wxID_ANY, "Start New Chat", wxDefaultPosition, wxSize(450, 280)) {

        auto* sizer = new wxBoxSizer(wxVERTICAL);

        sizer->Add(new wxStaticText(this, wxID_ANY, "Enter peer address and port to connect:"), 0, wxALL, 10);

        auto* address_sizer = new wxBoxSizer(wxHORIZONTAL);
        address_sizer->Add(new wxStaticText(this, wxID_ANY, "Address:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        address_input_ = new wxTextCtrl(this, wxID_ANY, "127.0.0.1");
        address_sizer->Add(address_input_, 1, wxEXPAND);
        sizer->Add(address_sizer, 0, wxEXPAND | wxALL, 10);

        auto* port_sizer = new wxBoxSizer(wxHORIZONTAL);
        port_sizer->Add(new wxStaticText(this, wxID_ANY, "Port:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        port_input_ = new wxTextCtrl(this, wxID_ANY, "12345");
        port_sizer->Add(port_input_, 1, wxEXPAND);
        sizer->Add(port_sizer, 0, wxEXPAND | wxALL, 10);

        auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
        auto* invite_btn = new wxButton(this, wxID_OK, "Connect");
        auto* cancel_btn = new wxButton(this, wxID_CANCEL, "Cancel");
        button_sizer->Add(invite_btn, 0, wxALL, 5);
        button_sizer->Add(cancel_btn, 0, wxALL, 5);
        sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(sizer);
        Centre();
    }

    std::string get_address() const { return address_input_->GetValue().ToStdString(); }
    std::string get_port() const { return port_input_->GetValue().ToStdString(); }

private:
    wxTextCtrl* address_input_;
    wxTextCtrl* port_input_;
};

class AliasDialog : public wxDialog {
public:
    AliasDialog(wxWindow* parent, const std::string& peer_id)
        : wxDialog(parent, wxID_ANY, "Set Alias", wxDefaultPosition, wxSize(400, 180)) {

        auto* sizer = new wxBoxSizer(wxVERTICAL);

        sizer->Add(new wxStaticText(this, wxID_ANY,
            "Set a local alias for peer " + truncateID(peer_id) + ":"), 0, wxALL, 10);

        alias_input_ = new wxTextCtrl(this, wxID_ANY);
        sizer->Add(alias_input_, 0, wxEXPAND | wxALL, 10);

        auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
        button_sizer->Add(new wxButton(this, wxID_OK, "OK"), 0, wxALL, 5);
        button_sizer->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxALL, 5);
        sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(sizer);
        Centre();
    }

    std::string get_alias() const { return alias_input_->GetValue().ToStdString(); }

private:
    wxTextCtrl* alias_input_;
};

class MyFrame : public wxFrame {
public:
    MyFrame(const wxString& title);
    ~MyFrame();

private:
    wxStaticText* user_id_label_;
    wxStaticText* port_label_;
    wxListBox* chat_list_;
    wxTextCtrl* chat_display_;
    wxTextCtrl* message_input_;
    wxButton* send_button_;
    wxButton* new_chat_button_;
    wxButton* end_chat_button_;

    std::string current_user_id_;
    std::map<std::string, ChatInfo> chats_;
    std::string active_chat_id_;

    unsigned char my_pk_[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk_[crypto_box_SECRETKEYBYTES];

    std::unique_ptr<P2PManager> p2p_manager_;

    void OnNewChat(wxCommandEvent& event);
    void OnSend(wxCommandEvent& event);
    void OnEndChat(wxCommandEvent& event);
    void OnChatSelected(wxCommandEvent& event);
    void OnMessageReceived(wxCommandEvent& event);
    void OnInvitationReceived(wxCommandEvent& event);
    void OnPeerConnected(wxCommandEvent& event);
    void OnPeerDisconnected(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);
    void OnChatListDClick(wxCommandEvent& event);

    void RefreshChatList();
    void LoadChatMessages(const std::string& chat_id);
    void RegenerateUserID();
    void RegenerateKeypair();
    std::string GetChatDisplayName(const ChatInfo& info) const;

    wxDECLARE_EVENT_TABLE();
};

enum {
    ID_Send = wxID_HIGHEST + 1,
    ID_NewChat,
    ID_EndChat,
    ID_ChatList
};

wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_BUTTON(ID_Send, MyFrame::OnSend)
    EVT_BUTTON(ID_NewChat, MyFrame::OnNewChat)
    EVT_BUTTON(ID_EndChat, MyFrame::OnEndChat)
    EVT_LISTBOX(ID_ChatList, MyFrame::OnChatSelected)
    EVT_LISTBOX_DCLICK(ID_ChatList, MyFrame::OnChatListDClick)
    EVT_COMMAND(wxID_ANY, wxEVT_MESSAGE_RECEIVED, MyFrame::OnMessageReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_INVITATION_RECEIVED, MyFrame::OnInvitationReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_PEER_CONNECTED, MyFrame::OnPeerConnected)
    EVT_COMMAND(wxID_ANY, wxEVT_PEER_DISCONNECTED, MyFrame::OnPeerDisconnected)
    EVT_CLOSE(MyFrame::OnClose)
wxEND_EVENT_TABLE()

class MyApp : public wxApp {
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit() {
    if (sodium_init() < 0) {
        wxMessageBox("Failed to initialize libsodium!", "Fatal Error", wxOK | wxICON_ERROR);
        return false;
    }
    auto* frame = new MyFrame("RetroMessenger - P2P Encrypted (Double Ratchet)");
    frame->Show(true);
    return true;
}

MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(900, 600)) {

    current_user_id_ = generateUniqueID();
    RegenerateKeypair();

    auto* main_sizer = new wxBoxSizer(wxVERTICAL);

    auto* top_bar = new wxPanel(this);
    auto* top_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto* info_sizer = new wxBoxSizer(wxVERTICAL);
    user_id_label_ = new wxStaticText(top_bar, wxID_ANY, "Your ID: " + current_user_id_);
    info_sizer->Add(user_id_label_, 0, wxALL, 5);
    port_label_ = new wxStaticText(top_bar, wxID_ANY, "Port: ...");
    info_sizer->Add(port_label_, 0, wxALL, 5);
    top_sizer->Add(info_sizer, 1, wxEXPAND);

    top_bar->SetSizer(top_sizer);
    main_sizer->Add(top_bar, 0, wxEXPAND | wxALL, 5);

    auto* content_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto* left_panel = new wxPanel(this);
    auto* left_sizer = new wxBoxSizer(wxVERTICAL);

    new_chat_button_ = new wxButton(left_panel, ID_NewChat, "+ Start New Chat");
    left_sizer->Add(new_chat_button_, 0, wxEXPAND | wxALL, 5);

    left_sizer->Add(new wxStaticText(left_panel, wxID_ANY, "Active Chats:"), 0, wxALL, 5);
    chat_list_ = new wxListBox(left_panel, ID_ChatList);
    left_sizer->Add(chat_list_, 1, wxEXPAND | wxALL, 5);

    left_sizer->Add(new wxStaticText(left_panel, wxID_ANY, "(Double-click chat to set alias)"), 0, wxLEFT | wxBOTTOM, 5);

    end_chat_button_ = new wxButton(left_panel, ID_EndChat, "End Chat");
    end_chat_button_->Enable(false);
    left_sizer->Add(end_chat_button_, 0, wxEXPAND | wxALL, 5);

    left_panel->SetSizer(left_sizer);
    content_sizer->Add(left_panel, 1, wxEXPAND | wxALL, 5);

    auto* right_panel = new wxPanel(this);
    auto* right_sizer = new wxBoxSizer(wxVERTICAL);

    chat_display_ = new wxTextCtrl(right_panel, wxID_ANY, "",
                                    wxDefaultPosition, wxDefaultSize,
                                    wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    right_sizer->Add(chat_display_, 1, wxEXPAND | wxALL, 5);

    auto* input_sizer = new wxBoxSizer(wxHORIZONTAL);
    message_input_ = new wxTextCtrl(right_panel, wxID_ANY, "",
                                     wxDefaultPosition, wxDefaultSize,
                                     wxTE_PROCESS_ENTER);
    message_input_->Enable(false);
    input_sizer->Add(message_input_, 1, wxEXPAND | wxALL, 5);

    send_button_ = new wxButton(right_panel, ID_Send, "Send");
    send_button_->Enable(false);
    input_sizer->Add(send_button_, 0, wxALL, 5);

    right_sizer->Add(input_sizer, 0, wxEXPAND);
    right_panel->SetSizer(right_sizer);
    content_sizer->Add(right_panel, 2, wxEXPAND | wxALL, 5);

    main_sizer->Add(content_sizer, 1, wxEXPAND);

    SetSizer(main_sizer);
    Centre();

    message_input_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent&) {
        if (!active_chat_id_.empty()) {
            wxCommandEvent dummy;
            OnSend(dummy);
        }
    });

    p2p_manager_ = std::make_unique<P2PManager>(this, my_pk_, my_sk_);
    port_label_->SetLabel(wxString::Format("Port: %d", p2p_manager_->get_listening_port()));
}

MyFrame::~MyFrame() {
    p2p_manager_.reset();
    sodium_memzero(my_sk_, sizeof(my_sk_));
    sodium_memzero(my_pk_, sizeof(my_pk_));
}

void MyFrame::OnNewChat(wxCommandEvent& event) {
    NewChatDialog dialog(this);
    if (dialog.ShowModal() == wxID_OK) {
        std::string peer_address = dialog.get_address();
        std::string peer_port = dialog.get_port();

        if (!peer_address.empty() && !peer_port.empty()) {
            p2p_manager_->send_invitation(peer_address, peer_port, current_user_id_);
            wxMessageBox("Invitation sent to " + peer_address + ":" + peer_port,
                         "Info", wxOK | wxICON_INFORMATION);
        }
    }
}

void MyFrame::OnSend(wxCommandEvent& event) {
    wxString message = message_input_->GetValue();
    if (message.IsEmpty() || active_chat_id_.empty()) {
        return;
    }

    std::string msg = message.ToStdString();

    auto& chat = chats_[active_chat_id_];

    auto encrypted = seal_message_ratchet(msg, chat.ratchet);
    auto framed = frame_encode(encrypted);
    p2p_manager_->send_raw(active_chat_id_, framed);

    chat.messageCache.push_back({truncateID(current_user_id_), msg});
    chat_display_->AppendText(truncateID(current_user_id_) + ": " + message + "\n");
    message_input_->Clear();
}

void MyFrame::OnEndChat(wxCommandEvent& event) {
    if (active_chat_id_.empty()) {
        return;
    }

    int answer = wxMessageBox("Are you sure you want to end this chat? Message history will be deleted.",
                             "Confirm", wxYES_NO | wxICON_QUESTION);

    if (answer == wxYES) {
        p2p_manager_->close_chat(active_chat_id_);

        auto it = chats_.find(active_chat_id_);
        if (it != chats_.end()) {
            it->second.ratchet.zero();
        }

        chats_.erase(active_chat_id_);
        active_chat_id_.clear();

        RegenerateUserID();
        RegenerateKeypair();

        RefreshChatList();
        chat_display_->Clear();
        message_input_->Enable(false);
        send_button_->Enable(false);
        end_chat_button_->Enable(false);
    }
}

void MyFrame::OnChatSelected(wxCommandEvent& event) {
    int selection = chat_list_->GetSelection();
    if (selection != wxNOT_FOUND) {
        int idx = 0;
        for (const auto& [chat_id, chat_info] : chats_) {
            if (chat_info.active) {
                if (idx == selection) {
                    active_chat_id_ = chat_id;
                    LoadChatMessages(chat_id);
                    message_input_->Enable(true);
                    send_button_->Enable(true);
                    end_chat_button_->Enable(true);
                    break;
                }
                ++idx;
            }
        }
    }
}

void MyFrame::OnChatListDClick(wxCommandEvent& event) {
    if (active_chat_id_.empty()) return;
    auto it = chats_.find(active_chat_id_);
    if (it == chats_.end()) return;

    AliasDialog dialog(this, it->second.peerID);
    if (dialog.ShowModal() == wxID_OK) {
        std::string alias = dialog.get_alias();
        if (!alias.empty()) {
            it->second.localAlias = alias;
            RefreshChatList();
        }
    }
}

void MyFrame::OnMessageReceived(wxCommandEvent& event) {
    auto* msg_data = static_cast<ReceivedMessageData*>(event.GetClientData());
    if (!msg_data) return;

    std::string chat_id = msg_data->chat_id;
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        std::string message = unseal_message_ratchet(
            msg_data->payload.data(), msg_data->payload.size(),
            it->second.ratchet);

        std::string sender_display = truncateID(it->second.peerID);
        it->second.messageCache.push_back({sender_display, message});

        if (chat_id == active_chat_id_) {
            chat_display_->AppendText(sender_display + ": " + message + "\n");
        }
    }
    delete msg_data;
}

void MyFrame::OnInvitationReceived(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');

    if (parts.GetCount() >= 3) {
        std::string peer_id = parts[0].ToStdString();
        std::string peer_pk_hex = parts[1].ToStdString();
        int pending_socket_id = 0;
        parts[2].ToLong(reinterpret_cast<long*>(&pending_socket_id));

        int answer = wxMessageBox(
            "Peer " + truncateID(peer_id) + " wants to start an encrypted chat. Accept?",
            "Chat Invitation", wxYES_NO | wxICON_QUESTION);

        if (answer == wxYES) {
            try {
                auto socket = p2p_manager_->take_pending_socket(pending_socket_id);

                std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
                std::string accept_msg = "ACCEPT:" + pk_hex + ":" + current_user_id_ + "\n";
                boost::asio::write(socket, boost::asio::buffer(accept_msg));

                auto peer_pk = hex_to_bytes(peer_pk_hex);
                if (peer_pk.size() != crypto_box_PUBLICKEYBYTES) {
                    wxLogError("Invalid peer public key");
                    return;
                }

                unsigned char shared_key[crypto_box_BEFORENMBYTES];
                if (crypto_box_beforenm(shared_key, peer_pk.data(), my_sk_) != 0) {
                    wxLogError("Failed to compute shared key");
                    return;
                }

                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(socket), this, chat_id);

                ChatInfo info;
                info.chatID = chat_id;
                info.peerID = peer_id;
                info.localAlias = "";
                info.active = true;
                info.is_initiator = false;

                init_ratchet(info.ratchet, shared_key, false);
                sodium_memzero(shared_key, sizeof(shared_key));

                chats_[chat_id] = info;

                p2p_manager_->add_session(chat_id, session);
                session->start();

                RegenerateUserID();
                RegenerateKeypair();

                RefreshChatList();
                wxMessageBox("Encrypted chat started with " + truncateID(peer_id),
                             "Success", wxOK | wxICON_INFORMATION);

            } catch (const std::exception& e) {
                wxLogError("Error accepting invitation: %s", e.what());
            }
        } else {
            try {
                auto socket = p2p_manager_->take_pending_socket(pending_socket_id);
                std::string reject_msg = "REJECT\n";
                boost::asio::write(socket, boost::asio::buffer(reject_msg));
            } catch (...) {
            }
        }
    }
}

void MyFrame::OnPeerConnected(wxCommandEvent& event) {
    auto* conn_data = static_cast<PeerConnectedData*>(event.GetClientData());
    if (!conn_data) return;

    ChatInfo info;
    info.chatID = conn_data->chat_id;
    info.peerID = conn_data->peer_id;
    info.localAlias = "";
    info.active = true;
    info.is_initiator = true;
    info.ratchet = conn_data->ratchet;

    chats_[conn_data->chat_id] = info;

    RegenerateUserID();
    RegenerateKeypair();

    RefreshChatList();
    wxMessageBox("Encrypted connection established with " + truncateID(conn_data->peer_id),
                 "Success", wxOK | wxICON_INFORMATION);

    delete conn_data;
}

void MyFrame::OnPeerDisconnected(wxCommandEvent& event) {
    std::string* chat_id_ptr = static_cast<std::string*>(event.GetClientData());
    if (!chat_id_ptr) return;

    std::string chat_id = *chat_id_ptr;
    delete chat_id_ptr;

    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        it->second.active = false;
        std::string name = GetChatDisplayName(it->second);

        if (chat_id == active_chat_id_) {
            chat_display_->AppendText("[" + name + " disconnected]\n");
            message_input_->Enable(false);
            send_button_->Enable(false);
        }

        it->second.ratchet.zero();
        RefreshChatList();
    }
}

void MyFrame::OnClose(wxCloseEvent& event) {
    for (auto& [id, info] : chats_) {
        info.ratchet.zero();
    }
    p2p_manager_.reset();
    event.Skip();
}

void MyFrame::RefreshChatList() {
    chat_list_->Clear();
    for (const auto& [chat_id, chat_info] : chats_) {
        if (chat_info.active) {
            chat_list_->Append(GetChatDisplayName(chat_info));
        }
    }
}

void MyFrame::LoadChatMessages(const std::string& chat_id) {
    chat_display_->Clear();
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        for (const auto& [sender, message] : it->second.messageCache) {
            chat_display_->AppendText(sender + ": " + message + "\n");
        }
    }
}

void MyFrame::RegenerateUserID() {
    current_user_id_ = generateUniqueID();
    user_id_label_->SetLabel("Your ID: " + current_user_id_);
}

void MyFrame::RegenerateKeypair() {
    sodium_memzero(my_sk_, sizeof(my_sk_));
    sodium_memzero(my_pk_, sizeof(my_pk_));
    crypto_box_keypair(my_pk_, my_sk_);
}

std::string MyFrame::GetChatDisplayName(const ChatInfo& info) const {
    if (!info.localAlias.empty()) {
        return info.localAlias;
    }
    return truncateID(info.peerID);
}

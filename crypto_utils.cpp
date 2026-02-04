#include "crypto_utils.h"
#include "compression.h"
#include <cstring>
#include <sodium.h>

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::string out(len * 2, '\0');
    sodium_bin2hex(&out[0], out.size() + 1, data, len);
    return out;
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> out(hex.size() / 2);
    size_t bin_len = 0;
    sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(),
                   nullptr, &bin_len, nullptr);
    out.resize(bin_len);
    return out;
}

static const size_t PAD_BLOCK_SIZE = 256;

std::vector<unsigned char> pad_data(const std::vector<unsigned char>& input) {
    size_t padded_len = ((input.size() / PAD_BLOCK_SIZE) + 1) * PAD_BLOCK_SIZE;
    std::vector<unsigned char> out(padded_len);
    std::memcpy(out.data(), input.data(), input.size());
    out[input.size()] = 0x80;
    for (size_t i = input.size() + 1; i < padded_len; ++i) {
        out[i] = 0x00;
    }
    return out;
}

std::vector<unsigned char> unpad_data(const std::vector<unsigned char>& input) {
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

void kdf_derive_pair(
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

void chain_advance(
    const unsigned char chain_key_in[32],
    unsigned char message_key_out[32],
    unsigned char chain_key_out[32])
{
    kdf_derive_pair(chain_key_in, 32, nullptr, 0, "chain",
                    message_key_out, chain_key_out);
}

void dh_ratchet_step(
    const unsigned char root_key_in[32],
    const unsigned char* dh_output, size_t dh_len,
    unsigned char root_key_out[32],
    unsigned char chain_key_out[32])
{
    kdf_derive_pair(root_key_in, 32, dh_output, dh_len, "ratchet",
                    root_key_out, chain_key_out);
}

void compute_message_hash(
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

void RatchetState::zero() {
    sodium_memzero(root_key, sizeof(root_key));
    sodium_memzero(send_chain_key, sizeof(send_chain_key));
    sodium_memzero(recv_chain_key, sizeof(recv_chain_key));
    sodium_memzero(my_eph_sk, sizeof(my_eph_sk));
    send_counter = 0;
    recv_counter = 0;
}

void init_ratchet(
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

std::vector<unsigned char> seal_message_ratchet(
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

std::string unseal_message_ratchet(
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

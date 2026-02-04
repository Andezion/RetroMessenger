#pragma once

#include <string>
#include <vector>
#include <sodium.h>

std::string bytes_to_hex(const unsigned char* data, size_t len);
std::vector<unsigned char> hex_to_bytes(const std::string& hex);

std::vector<unsigned char> pad_data(const std::vector<unsigned char>& input);
std::vector<unsigned char> unpad_data(const std::vector<unsigned char>& input);

void kdf_derive_pair(
    const unsigned char* input_key, size_t input_len,
    const unsigned char* salt, size_t salt_len,
    const char* context,
    unsigned char out_key1[32],
    unsigned char out_key2[32]);

void chain_advance(
    const unsigned char chain_key_in[32],
    unsigned char message_key_out[32],
    unsigned char chain_key_out[32]);

void dh_ratchet_step(
    const unsigned char root_key_in[32],
    const unsigned char* dh_output, size_t dh_len,
    unsigned char root_key_out[32],
    unsigned char chain_key_out[32]);

void compute_message_hash(
    const unsigned char* prev_hash,
    const unsigned char* ciphertext, size_t ciphertext_len,
    uint32_t counter,
    unsigned char out_hash[32]);

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

    void zero();
};

void init_ratchet(
    RatchetState& ratchet,
    const unsigned char initial_shared_key[crypto_box_BEFORENMBYTES],
    bool is_initiator);

std::vector<unsigned char> seal_message_ratchet(
    const std::string& message,
    RatchetState& ratchet);

std::string unseal_message_ratchet(
    const unsigned char* data, size_t len,
    RatchetState& ratchet);

std::string generateUniqueID();
std::string truncateID(const std::string& id);

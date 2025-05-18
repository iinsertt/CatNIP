
#include "session.h"
#include "core.h"
#include <cstring>
#include <ostream>
using namespace catnip;

CatSession::CatSession() {
    secure_memzero(private_key, CAT_KEY_SIZE);
    secure_memzero(public_key, CAT_KEY_SIZE);
    secure_memzero(peer_public_key, CAT_KEY_SIZE);
    secure_memzero(shared_secret, SHARED_SECRET_SIZE);
    secure_memzero(challenge, CAT_CHALLENGE_SIZE);
}

CatSession::~CatSession() {
    secure_memzero(private_key, CAT_KEY_SIZE);
    secure_memzero(public_key, CAT_KEY_SIZE);
    secure_memzero(peer_public_key, CAT_KEY_SIZE);
    secure_memzero(shared_secret, SHARED_SECRET_SIZE);
    secure_memzero(challenge, CAT_CHALLENGE_SIZE);
}

void CatSession::generate_keypair() {
    random_bytes(private_key, CAT_KEY_SIZE);
    crypto_scalarmult_base(public_key, private_key);
}

void CatSession::load_peer_public_key(const uint8_t* data) {
    memcpy(peer_public_key, data, CAT_KEY_SIZE);
}

void CatSession::derive_shared_secret() {
    crypto_scalarmult(shared_secret, private_key, peer_public_key);
}

void CatSession::initiate_handshake() {
    random_bytes(challenge, CAT_CHALLENGE_SIZE);
}

bool CatSession::finalize_handshake(const uint8_t* peer_data) {
    return memcmp(peer_data, challenge, CAT_CHALLENGE_SIZE) == 0;
}

bool CatSession::verify_challenge_response(const uint8_t* response) {
    uint8_t expected[CAT_HMAC_SIZE];
    crypto_auth_hmacsha256(expected, challenge, CAT_CHALLENGE_SIZE, shared_secret);
    return constant_time_compare(expected, response, CAT_HMAC_SIZE);
}

void CatSession::get_public_key(uint8_t* out) const {
    memcpy(out, public_key, CAT_KEY_SIZE);
}

void CatSession::get_challenge(uint8_t* out) const {
    memcpy(out, challenge, CAT_CHALLENGE_SIZE);
}

void CatSession::writeServer_challenge_response(const uint8_t* response) {
    memcpy(server_challenge, response, CAT_CHALLENGE_SIZE)
    ;
}

void CatSession::generate_challenge_response(uint8_t* out) const {
    crypto_auth_hmacsha256(out, server_challenge, CAT_CHALLENGE_SIZE, shared_secret);
}

const uint8_t* CatSession::get_shared_secret() const {
    return shared_secret;
}

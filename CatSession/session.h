#ifndef SESSION_H
#define SESSION_H

#include <iomanip>

#include "core.h"
#include "iostream"

namespace catnip {
    class CatSession {
    public:
        CatSession();

        ~CatSession();

        void generate_keypair();

        void load_peer_public_key(const uint8_t *data);

        void derive_shared_secret();

        void initiate_handshake();

        bool finalize_handshake(const uint8_t *peer_data);

        bool verify_challenge_response(const uint8_t *response);

        void get_public_key(uint8_t *out) const;

        void get_challenge(uint8_t *out) const;

        void writeServer_challenge_response(const uint8_t *response);

        void generate_challenge_response(uint8_t *out) const;

        const uint8_t *get_shared_secret() const;

        static void print_hex(const char *label, const uint8_t *data, size_t len) {
            std::cout << label;
            for (size_t i = 0; i < len; ++i)
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[i];
            std::cout << std::dec << std::endl;
        }

    private:
        uint8_t private_key[CAT_KEY_SIZE]{};
        uint8_t public_key[CAT_KEY_SIZE]{};
        uint8_t peer_public_key[CAT_KEY_SIZE]{};
        uint8_t shared_secret[SHARED_SECRET_SIZE]{};

        uint8_t challenge[CAT_CHALLENGE_SIZE]{};
        uint8_t server_challenge[CAT_CHALLENGE_SIZE];
    };
}

#endif


#ifndef STREAM_H
#define STREAM_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <atomic>
#include <mutex>

namespace catnip {

    constexpr size_t MATRIX_SIZE = 256 * 256;
    constexpr size_t KEY_SIZE = 32;
    constexpr size_t NONCE_SIZE = 12;
    constexpr size_t HMAC_SIZE = 32;

    class StreamCipher {
    public:
        StreamCipher();

        void initialize(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len);
        void encrypt(uint8_t* data, size_t len, uint8_t* out_tag);
        bool decrypt(uint8_t* data, size_t len, const uint8_t* in_tag);
        void rotate_matrix();

    private:
        void derive_matrix_key();
        void generate_sync_matrix();

        std::array<uint8_t, MATRIX_SIZE> sync_matrix;
        std::array<uint8_t, KEY_SIZE> key;
        std::array<uint8_t, NONCE_SIZE> nonce;
        std::array<uint8_t, KEY_SIZE> hkdf_temp;
        std::atomic<uint64_t> counter;
        std::mutex mutex;
    };

} // namespace catnip

#endif // STREAM_H

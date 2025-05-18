
#include "core.h"
#include <cstring>
#include <chrono>

namespace catnip {

    SecureBuffer::SecureBuffer(size_t sz) : data(nullptr), size(sz) {
        data = (uint8_t*)sodium_malloc(size);
        if (!data) abort();
        memset(data, 0, size);
    }

    SecureBuffer::~SecureBuffer() {
        if (data) {
            sodium_memzero(data, size);
            sodium_free(data);
        }
    }

    void SecureBuffer::zero() {
        if (data && size) sodium_memzero(data, size);
    }

    uint64_t now_millis() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    }

    void hex_encode(const void* in, size_t len, char* out) {
        static const char* hex = "0123456789abcdef";
        const uint8_t* src = (const uint8_t*)in;
        for (size_t i = 0; i < len; ++i) {
            out[i * 2] = hex[src[i] >> 4];
            out[i * 2 + 1] = hex[src[i] & 0x0F];
        }
    }

    bool hex_decode(const char* in, size_t len, void* out) {
        if (len % 2 != 0) return false;
        uint8_t* dst = (uint8_t*)out;
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (size_t i = 0; i < len / 2; ++i) {
            int hi = hex_val(in[i * 2]);
            int lo = hex_val(in[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            dst[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }

}

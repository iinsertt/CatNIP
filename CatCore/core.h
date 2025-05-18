
#ifndef CAT_CORE_H
#define CAT_CORE_H

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <openssl/rand.h>
#include <sodium.h>


#define CAT_VERSION_MAJOR 1;
#define CAT_VERSION_MINOR 0;
#define CAT_VERSION_PATCH 0;

#define CAT_FORCE_INLINE inline __attribute__((always_inline))
#define CAT_NODISCARD [[nodiscard]]
#define CAT_NO_COPY(Type) Type(const Type&) = delete; Type& operator=(const Type&) = delete;
#define CAT_NO_MOVE(Type) Type(Type&&) = delete; Type& operator=(Type&&) = delete;
#define CAT_NO_COPY_MOVE(Type) CAT_NO_COPY(Type) CAT_NO_MOVE(Type)

#define CAT_SECURE_ZERO(ptr, size) sodium_memzero((ptr), (size))
#define CAT_RANDOM_BYTES(buf, len) RAND_bytes((unsigned char*)(buf), (int)(len))

constexpr size_t CAT_KEY_SIZE = 32;
constexpr size_t CAT_NONCE_SIZE = 12;
constexpr size_t CAT_TAG_SIZE = 16;
constexpr size_t CAT_CHALLENGE_SIZE = 32;
constexpr size_t CAT_MATRIX_SIZE = 256 * 256;
constexpr size_t CAT_HMAC_SIZE = 32;
constexpr size_t SHARED_SECRET_SIZE = 32;



namespace catnip {

enum class Status : uint8_t {
    OK = 0,
    Error,
    Invalid,
    CryptoError,
    Timeout,
    Disconnected
};

struct alignas(16) SecureBuffer {
    uint8_t* data;
    size_t size;

    SecureBuffer(size_t sz);
    ~SecureBuffer();

    void zero();
    uint8_t* ptr() const { return data; }
    size_t len() const { return size; }

    CAT_NO_COPY_MOVE(SecureBuffer)
};

class AtomicCounter {
    std::atomic<uint64_t> value;

public:
    AtomicCounter() : value(0) {}
    void reset() { value.store(0, std::memory_order_relaxed); }
    uint64_t next() { return value.fetch_add(1, std::memory_order_relaxed); }
    uint64_t get() const { return value.load(std::memory_order_relaxed); }
};

class SpinLock {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
public:
    void lock() {
        while (flag.test_and_set(std::memory_order_acquire)) {}
    }
    void unlock() {
        flag.clear(std::memory_order_release);
    }
};

uint64_t now_millis();
void hex_encode(const void* in, size_t len, char* out);
bool hex_decode(const char* in, size_t len, void* out);

    inline void secure_memzero(void* ptr, size_t len) {
#if defined(SODIUM_LIBRARY_VERSION_MAJOR)
        sodium_memzero(ptr, len);
#else
        OPENSSL_cleanse(ptr, len);
#endif
    }

    inline void random_bytes(uint8_t* buf, size_t len) {
#if defined(SODIUM_LIBRARY_VERSION_MAJOR)
        randombytes_buf(buf, len);
#else
        RAND_bytes(buf, len);
#endif
    }

    inline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
#if defined(SODIUM_LIBRARY_VERSION_MAJOR)
        return sodium_memcmp(a, b, len) == 0;
#else
        return CRYPTO_memcmp(a, b, len) == 0;
#endif
    }

    inline void crypto_scalarmult_base(uint8_t* pub, const uint8_t* priv) {
        auto zacroy_ebalo = crypto_scalarmult_curve25519_base(pub, priv);
    }

    inline void crypto_scalarmult(uint8_t* out, const uint8_t* priv, const uint8_t* pub) {
        auto zacroy_ebalo = crypto_scalarmult_curve25519(out, priv, pub);
    }

    inline void crypto_auth_hmacsha256(uint8_t* out, const uint8_t* msg, size_t msg_len, const uint8_t* key) {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, key, 32);
        crypto_auth_hmacsha256_update(&state, msg, msg_len);
        crypto_auth_hmacsha256_final(&state, out);
    }



}

#endif // CAT_CORE_H


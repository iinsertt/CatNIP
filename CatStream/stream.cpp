
#include "stream.h"

#include "core.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
namespace catnip {

    StreamCipher::StreamCipher()
        : sync_matrix{}, key{}, nonce{}, hkdf_temp{}, counter(0) {
    sync_matrix.fill(0);
    key.fill(0);
    nonce.fill(0);
    hkdf_temp.fill(0);
}

void StreamCipher::initialize(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len) {
    std::lock_guard<std::mutex> lock(mutex);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t outlen = KEY_SIZE;
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, KEY_SIZE);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char *>("CatStream-Matrix"), 16);
    EVP_PKEY_derive(pctx, hkdf_temp.data(), &outlen);
    EVP_PKEY_CTX_free(pctx);

    key = hkdf_temp;
    generate_sync_matrix();
}

void StreamCipher::generate_sync_matrix() {
    std::array<uint8_t, MATRIX_SIZE> buffer{};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), nonce.data());
    EVP_EncryptUpdate(ctx, buffer.data(), &len, buffer.data(), MATRIX_SIZE);
    EVP_CIPHER_CTX_free(ctx);

    sync_matrix = buffer;
}

void StreamCipher::rotate_matrix() {
    std::lock_guard<std::mutex> lock(mutex);
    for (size_t i = 0; i < MATRIX_SIZE; ++i)
        sync_matrix[i] ^= static_cast<uint8_t>((counter.load() >> (i % 8)) & 0xFF);
}

void StreamCipher::encrypt(uint8_t* data, size_t len, uint8_t* out_tag) {
    std::lock_guard<std::mutex> lock(mutex);
    for (size_t i = 0; i < len; ++i)
        data[i] ^= sync_matrix[(counter + i) % MATRIX_SIZE];
    crypto_auth_hmacsha256(out_tag, data, len, key.data());
    counter += len;
}

bool StreamCipher::decrypt(uint8_t* data, size_t len, const uint8_t* in_tag) {
    std::lock_guard<std::mutex> lock(mutex);
    uint8_t computed[HMAC_SIZE];
    crypto_auth_hmacsha256(computed, data, len, key.data());
    if (!constant_time_compare(computed, in_tag, HMAC_SIZE)) return false;
    for (size_t i = 0; i < len; ++i)
        data[i] ^= sync_matrix[(counter + i) % MATRIX_SIZE];

    counter += len;
    return true;
}

} // namespace catnip

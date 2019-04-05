#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t input[16]; // current input, unencrypted
    uint32_t pool [16]; // last input, encrypted
    size_t   pool_idx;  // pointer to random_pool
} crypto_chacha_ctx;

void crypto_chacha20_H(      uint8_t out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

void crypto_chacha20_init(      crypto_chacha_ctx* ctx,
                          const uint8_t            key[32],
                          const uint8_t            nonce[8]);

void crypto_chacha20_x_init(      crypto_chacha_ctx* ctx,
                            const uint8_t            key[32],
                            const uint8_t            nonce[24]);

void crypto_chacha20_set_ctr(      crypto_chacha_ctx* ctx,
                             const uint64_t           ctr);

void crypto_chacha20_encrypt(      crypto_chacha_ctx* ctx,
                                   uint8_t*           cipher_text,
                             const uint8_t*           plain_text,
                             const size_t             text_size);

void crypto_chacha20_stream(      crypto_chacha_ctx* ctx,
                                  uint8_t*           stream,
                            const size_t             size);

#ifdef __cplusplus
}
#endif
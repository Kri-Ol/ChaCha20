#include <algorithm>

#include "chacha20.hpp"


#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))
#define ALIGN(x, block_size) ((~(x) + 1) & ((block_size) - 1))


void crypto_wipe(      void*  secret,
                 const size_t size   )
{
    volatile uint8_t* v_secret = (uint8_t*)secret;
    FOR (i, 0, size) {
        v_secret[i] = 0;
    }
}


static inline uint32_t rotl32(const uint32_t x,
                              const uint32_t n)
{
    return (x << n) ^ (x >> (32 - n));
}


static inline uint32_t load32_le(const uint8_t s[4])
{
    return (uint32_t)s[0]
        | ((uint32_t)s[1] <<  8)
        | ((uint32_t)s[2] << 16)
        | ((uint32_t)s[3] << 24);
}


static inline void store32_le(      uint8_t  out[4],
                              const uint32_t in     )
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}


#define QUARTERROUND(a, b, c, d)     \
    a += b;  d = rotl32(d ^ a, 16);  \
    c += d;  b = rotl32(b ^ c, 12);  \
    a += b;  d = rotl32(d ^ a,  8);  \
    c += d;  b = rotl32(b ^ c,  7)


static void chacha20_rounds(      uint32_t out[16],
                            const uint32_t in[16])
{
    // The temporary variables make Chacha20 10% faster.
    uint32_t t0  = in[ 0];  uint32_t t1  = in[ 1];  uint32_t t2  = in[ 2];  uint32_t t3  = in[ 3];
    uint32_t t4  = in[ 4];  uint32_t t5  = in[ 5];  uint32_t t6  = in[ 6];  uint32_t t7  = in[ 7];
    uint32_t t8  = in[ 8];  uint32_t t9  = in[ 9];  uint32_t t10 = in[10];  uint32_t t11 = in[11];
    uint32_t t12 = in[12];  uint32_t t13 = in[13];  uint32_t t14 = in[14];  uint32_t t15 = in[15];

    FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
        QUARTERROUND(t0, t4, t8 , t12); // column 0
        QUARTERROUND(t1, t5, t9 , t13); // column 1
        QUARTERROUND(t2, t6, t10, t14); // column 2
        QUARTERROUND(t3, t7, t11, t15); // column 3
        QUARTERROUND(t0, t5, t10, t15); // diagonal 0
        QUARTERROUND(t1, t6, t11, t12); // diagonal 1
        QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
        QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
    }
    out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
    out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
    out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
    out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}


static void chacha20_init_key(      crypto_chacha_ctx* ctx,
                              const uint8_t            key[32])
{
    // constant
    ctx->input[0] = load32_le((uint8_t*)"expa");
    ctx->input[1] = load32_le((uint8_t*)"nd 3");
    ctx->input[2] = load32_le((uint8_t*)"2-by");
    ctx->input[3] = load32_le((uint8_t*)"te k");
    // key
    FOR (i, 0, 8) {
        ctx->input[i+4] = load32_le(key + i*4);
    }
}


static uint8_t chacha20_pool_byte(crypto_chacha_ctx* ctx)
{
    uint32_t pool_word = ctx->pool[ctx->pool_idx >> 2];
    uint8_t  pool_byte = pool_word >> (8*(ctx->pool_idx & 3));
    ctx->pool_idx++;
    return pool_byte;
}


// Fill the pool if needed, update the counters
static void chacha20_refill_pool(crypto_chacha_ctx* ctx)
{
    chacha20_rounds(ctx->pool, ctx->input);
    FOR (j, 0, 16) {
        ctx->pool[j] += ctx->input[j];
    }
    ctx->pool_idx = 0;
    ctx->input[12]++;
    if (ctx->input[12] == 0) {
        ctx->input[13]++;
    }
}


void crypto_chacha20_H(      uint8_t out[32],
                       const uint8_t key[32],
                       const uint8_t in[16])
{
    crypto_chacha_ctx ctx;
    chacha20_init_key(&ctx, key);
    FOR (i, 0, 4) {
        ctx.input[i+12] = load32_le(in + i*4);
    }
    uint32_t buffer[16];
    chacha20_rounds(buffer, ctx.input);
    // prevents reversal of the rounds by revealing only half of the buffer.
    FOR (i, 0, 4) {
        store32_le(out      + i*4, buffer[i     ]); // constant
        store32_le(out + 16 + i*4, buffer[i + 12]); // counter and nonce
    }
    WIPE_CTX(&ctx);
    WIPE_BUFFER(buffer);
}


static void chacha20_encrypt(      crypto_chacha_ctx* ctx,
                                   uint8_t*           cipher_text,
                             const uint8_t*           plain_text,
                             const size_t             text_size) {
    FOR (i, 0, text_size) {
        if (ctx->pool_idx == 64) {
            chacha20_refill_pool(ctx);
        }
        uint8_t plain = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = chacha20_pool_byte(ctx) ^ plain;
        cipher_text++;
    }
}


void crypto_chacha20_init(      crypto_chacha_ctx* ctx,
                          const uint8_t            key[32],
                          const uint8_t            nonce[8])
{
    chacha20_init_key      (ctx, key);     // key
    crypto_chacha20_set_ctr(ctx, 0  );     // counter
    ctx->input[14] = load32_le(nonce + 0); // nonce
    ctx->input[15] = load32_le(nonce + 4); // nonce
}


void crypto_chacha20_x_init(      crypto_chacha_ctx* ctx,
                            const uint8_t            key[32],
                            const uint8_t            nonce[24])
{
    uint8_t derived_key[32];
    crypto_chacha20_H(derived_key, key, nonce);
    crypto_chacha20_init(ctx, derived_key, nonce + 16);
    WIPE_BUFFER(derived_key);
}


void crypto_chacha20_set_ctr(      crypto_chacha_ctx* ctx,
                             const uint64_t           ctr)
{
    ctx->input[12] = ctr & 0xffffffff;
    ctx->input[13] = ctr >> 32;
    ctx->pool_idx  = 64;  // The random pool (re)starts empty
}


void crypto_chacha20_encrypt(      crypto_chacha_ctx* ctx,
                                   uint8_t*           cipher_text,
                             const uint8_t*           plain_text,
                             const size_t             text_size_)
{
    // Align ourselves with block boundaries
    size_t text_size = text_size_;

    size_t align = std::min(ALIGN(ctx->pool_idx, 64), text_size);
    chacha20_encrypt(ctx, cipher_text, plain_text, align);
    if (plain_text != 0) {
        plain_text += align;
    }
    cipher_text += align;
    text_size   -= align;

    // Process the message block by block
    FOR (i, 0, text_size >> 6) {  // number of blocks
        chacha20_refill_pool(ctx);
        if (plain_text != 0) {
            FOR (j, 0, 16) {
                uint32_t plain = load32_le(plain_text);
                store32_le(cipher_text, ctx->pool[j] ^ plain);
                plain_text  += 4;
                cipher_text += 4;
            }
        } else {
            FOR (j, 0, 16) {
                store32_le(cipher_text, ctx->pool[j]);
                cipher_text += 4;
            }
        }
        ctx->pool_idx = 64;
    }
    text_size &= 63;

    // remaining bytes
    chacha20_encrypt(ctx, cipher_text, plain_text, text_size);
}


void crypto_chacha20_stream(      crypto_chacha_ctx* ctx,
                                  uint8_t*           stream,
                            const size_t             size)
{
    crypto_chacha20_encrypt(ctx, stream, 0, size);
}

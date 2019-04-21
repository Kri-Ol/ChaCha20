#include <algorithm>
#include <memory>
#include <iostream>

#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "chacha20.hpp"


static constexpr char NL = '\n';

static void hex2byte(const char*    hex,
                           uint8_t* byte)
{
    while (*hex) {
        sscanf_s(hex, "%2hhx", byte++);
        hex += 2;
    }
}


static void test_ietf_chacha20(const char*    text_key,
                               const char*    text_nonce,
                               const char*    text_plain,
                               const char*    text_cipher,
                               const uint64_t counter,
                               const uint32_t number)
{
    size_t len = strlen(text_plain) / 2;

    auto plain  = std::unique_ptr<uint8_t[]>{ new uint8_t [len] };
    auto cipher = std::unique_ptr<uint8_t[]>{ new uint8_t [len] };
    auto output = std::unique_ptr<uint8_t[]>{ new uint8_t [len] };

    std::cout << "Test Vector: Encipherment #" << number << ": ";

    uint8_t key[32];
    hex2byte(text_key, key);

    uint8_t nonce[8];
    hex2byte(text_nonce, nonce);

    hex2byte(text_plain, plain.get());
    hex2byte(text_cipher, cipher.get());

    crypto_chacha_ctx ctx;
    crypto_chacha20_init(&ctx, key, nonce);

    // Exact length test
    memset(output.get(), 0, len);
    crypto_chacha20_set_ctr(&ctx, counter);

    crypto_chacha20_encrypt(&ctx, output.get(), plain.get(), len);

    if (memcmp(output.get(), cipher.get(), len)) {
        std::cerr << "Failed exact length" << NL;
        return;
    }

    // Fixed length tests
    for (size_t i = 1; i != len; ++i) {
        memset(output.get(), 0, len);
        crypto_chacha20_set_ctr(&ctx, counter);
        for (size_t j = 0; j < len; j += i) {
            crypto_chacha20_encrypt(&ctx, output.get() + j, plain.get() + j, std::min(i, len-j));
        }
        if (memcmp(output.get(), cipher.get(), len)) {
            std::cerr << "Failed at round: " << i << NL;
            return;
        }
    }

    // Random length tests 1
    for (size_t i = 0; i != 1000; ++i) {
        memset(output.get(), 0, len);
        crypto_chacha20_set_ctr(&ctx, counter);
        for (size_t j = 0, amount; j < len; j += amount) {
            amount = rand() & 15;
            crypto_chacha20_encrypt(&ctx, output.get() + j, plain.get() + j, std::min(amount, len-j));
        }
        if (memcmp(output.get(), cipher.get(), len)) {
            std::cerr << "Failed random tests 1" << NL;
            return;
        }
    }

    // Random length tests 2
    for (size_t i = 0; i != 1000; ++i) {
        memset(output.get(), 0, len);
        crypto_chacha20_set_ctr(&ctx, counter);
        for (size_t j = 0, amount; j < len; j += amount) {
            amount = 65 + (rand() & 63);
            crypto_chacha20_encrypt(&ctx, output.get() + j, plain.get() + j, std::min(amount, len-j));
        }
        if (memcmp(output.get(), cipher.get(), len)) {
            std::cerr << "Failed random tests 2" << NL;
            return;
        }
    }
    std::cout << "Success" << NL;
}


uint64_t scramble(const uint64_t groupId,
                  const uint64_t recordId,
                  const char*    text_key = nullptr)
{
    uint8_t key[32] = {0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
                       0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                       0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
                       0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0}; // same key as in example 3 below
    if (text_key != nullptr) {
        hex2byte(text_key, key);
    }

    const uint8_t* nonce = reinterpret_cast<const uint8_t*>(&groupId); // nonce would be our group id
    crypto_chacha_ctx ctx;
    crypto_chacha20_init(&ctx, key, nonce); // initialize ChaCha20

    crypto_chacha20_set_ctr(&ctx, recordId); // block counter is our record Id

    uint64_t input = 0x0000000000000000; // Just get the block out. Chacha will make random block and XOR it with input text.
                                         // XOR with zeroes preserve Chacha block.
                                         // Or 0xFFFFFFFFFFFFFFFF to get it inverted
    uint64_t output;
    crypto_chacha20_encrypt(&ctx,
                            reinterpret_cast<uint8_t*>(&output),
                            reinterpret_cast<const uint8_t*>(&input),
                            sizeof(input));

    return output;
}


int main()
{
    // Test values from http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2
    srand(123); //Test results will be consistent
    test_ietf_chacha20("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0, 1);
    test_ietf_chacha20("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1, 2);
    test_ietf_chacha20("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42, 3);
    std::cout << NL;

    uint64_t scrambled{0ULL};

    scrambled = scramble(10, 12345);
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(100, 12345);
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(11, 12345); // group id differ by 1
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(10, 12346); // record id differ by 1
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(0, 0);
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(0, 1);
    std::cout << "0x" << std::hex << scrambled << NL;
    scrambled = scramble(1, 0);
    std::cout << "0x" << std::hex << scrambled << NL;

    return 0;
}

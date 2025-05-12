#include "lorawan_crypto.h"
#include "mbedtls/cmac.h"
#include "mbedtls/aes.h"

uint32_t lorawan_aes_cmac(const uint8_t *key, const uint8_t *input, size_t len)
{
    uint8_t mac[16];
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

    mbedtls_cipher_init(&ctx);
    mbedtls_cipher_setup(&ctx, cipher_info);
    mbedtls_cipher_cmac_starts(&ctx, key, 128);
    mbedtls_cipher_cmac_update(&ctx, input, len);
    mbedtls_cipher_cmac_finish(&ctx, mac);
    mbedtls_cipher_free(&ctx);

    return (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) | ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
}

void aes128_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output);
    mbedtls_aes_free(&aes);
}
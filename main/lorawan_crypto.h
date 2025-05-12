#pragma once
#include <stdint.h>
#include <stddef.h>

// Return 32‑bit MIC (LSB) of input using AES‑CMAC with given key
uint32_t lorawan_aes_cmac(const uint8_t *key, const uint8_t *input, size_t len);

// AES‑128 ECB encrypt helper (16‑byte block)
void aes128_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output);

#include <stdint.h>
#include <stdio.h>
#include "monocypher-ed25519.h"

uint8_t private_key[64];
uint8_t public_key[32];
uint8_t seed[32];

void generate_keys(uint8_t *private_key, uint8_t *public_key) {
    uint8_t seed[32];

    // TODO use actual seed generation in the future
    for (size_t i = 0; i<sizeof(seed); ++i) {
        seed[i] = i;
    }
    // generate keys
    crypto_ed25519_key_pair(private_key, public_key, seed);
    crypto_wipe(seed, sizeof(seed));
}

void sign(uint8_t signature [64], const uint8_t private_key[64], const void *message, size_t message_size) {
    crypto_ed25519_sign(signature, private_key, (const uint8_t *)message, message_size);
}

int verify(const uint8_t signature [64], const uint8_t public_key[32], const void *message, size_t message_size) {
    return crypto_ed25519_check(signature, public_key, (const uint8_t*) message, message_size);
}





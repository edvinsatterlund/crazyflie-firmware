
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "monocypher-ed25519.h"
#include "stm32f4xx.h"
#include "storage.h"

static bool rngInitialized = false;

#define DRIP_KEYPAIR_MAGIC 0x44524950UL
#define DRIP_KEYPAIR_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t private_key[64];
    uint8_t public_key[32];
} dripKeyPair_t;

void rngInit(void)
{
    if (rngInitialized) return;

    RCC->AHB2ENR |= RCC_AHB2ENR_RNGEN;
    RNG->CR |= RNG_CR_RNGEN;
    rngInitialized = true;
}

// Returns true on success
bool rngGetBytes(uint8_t *buf, size_t len)
{
    rngInit();

    uint32_t prev = 0;
    bool havePrev = false;

    while (len > 0) {
        // Wait for data ready, with a timeout
        uint32_t timeout = 100000;
        while ((RNG->SR & RNG_SR_DRDY) == 0) {
            if ((RNG->SR & RNG_SR_CECS) != 0 ||
                (RNG->SR & RNG_SR_SECS) != 0) {
                // Clock or seed error: clear flags and reinitialize
                RNG->SR = ~((RNG_SR_CECS | RNG_SR_SECS) << 4);
                RNG->CR &= ~RNG_CR_RNGEN;
                RNG->CR |= RNG_CR_RNGEN;
            }
            if (--timeout == 0) return false;
        }

        uint32_t r = RNG->DR;

        // Per ST's recommendation: discard the first value and
        // reject consecutive identical values (continuous self-test)
        if (!havePrev || r == prev) {
            prev = r;
            havePrev = true;
            continue;
        }
        prev = r;

        size_t n = len < 4 ? len : 4;
        memcpy(buf, &r, n);
        buf += n;
        len -= n;
    }
    return true;
}



bool generate_keys(uint8_t *private_key, uint8_t *public_key) {
    dripKeyPair_t key_pair;

    if (storageFetch("drip/keypair", &key_pair, sizeof(key_pair)) == sizeof(key_pair) &&
        key_pair.magic == DRIP_KEYPAIR_MAGIC &&
        key_pair.version == DRIP_KEYPAIR_VERSION) {
        memcpy(private_key, key_pair.private_key, sizeof(key_pair.private_key));
        memcpy(public_key, key_pair.public_key, sizeof(key_pair.public_key));
        crypto_wipe(&key_pair, sizeof(key_pair));
        return true;
    }

    uint8_t seed[32];
    if (!rngGetBytes(seed, sizeof(seed))) {
        crypto_wipe(seed, sizeof(seed));
        crypto_wipe(private_key, 64);
        crypto_wipe(public_key, 32);
        crypto_wipe(&key_pair, sizeof(key_pair));
        return false;
    }

    crypto_ed25519_key_pair(private_key, public_key, seed);
    crypto_wipe(seed, sizeof(seed));

    key_pair.magic = DRIP_KEYPAIR_MAGIC;
    key_pair.version = DRIP_KEYPAIR_VERSION;
    memcpy(key_pair.private_key, private_key, sizeof(key_pair.private_key));
    memcpy(key_pair.public_key, public_key, sizeof(key_pair.public_key));

    bool stored = storageStore("drip/keypair", &key_pair, sizeof(key_pair));
    crypto_wipe(&key_pair, sizeof(key_pair));
    return stored;
}

void sign(uint8_t signature [64], const uint8_t private_key[64], const void *message, size_t message_size) {
    crypto_ed25519_sign(signature, private_key, (const uint8_t *)message, message_size);
}

int verify(const uint8_t signature [64], const uint8_t public_key[32], const void *message, size_t message_size) {
    return crypto_ed25519_check(signature, public_key, (const uint8_t*) message, message_size);
}





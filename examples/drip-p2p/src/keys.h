#ifndef CRYPTOTEST_H
#define CRYPTOTEST_H

#include <stdint.h>
#include <stdio.h>

void generate_keys(uint8_t *private_key, uint8_t *public_key);
void sign(uint8_t signature [64], const uint8_t private_key[64], const void *message, size_t message_size);
int verify(const uint8_t signature [64], const uint8_t public_key[32], const void *message, size_t message_size) ;

#endif
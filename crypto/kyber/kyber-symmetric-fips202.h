#ifndef KYBER_SYMMETRIC_FIPS_H
#define KYBER_SYMMETRIC_FIPS_H

#include "../dilithium/fips202.h"

void kyber_shake128_absorb(keccak_state *s, const unsigned char *input, unsigned char x, unsigned char y);
void kyber_shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, keccak_state *s);
void shake256_prf(unsigned char *output, unsigned long long outlen, const unsigned char *key, const unsigned char nonce);
void shake256(unsigned char *output, unsigned long long outlen,
              const unsigned char *input,  unsigned long long inlen);

#endif

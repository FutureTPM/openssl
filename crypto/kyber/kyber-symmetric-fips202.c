#include <stdlib.h>
#include "../dilithium/fips202.h"
#include "kyber-params.h"
#include "openssl/evp.h"

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
*              - const unsigned char *input:      pointer to KYBER_SYMBYTES input to be absorbed into s
*              - unsigned char i                  additional byte of input
*              - unsigned char j                  additional byte of input
**************************************************/
void kyber_shake128_absorb(keccak_state *s, const unsigned char *input, unsigned char x, unsigned char y)
{
  unsigned char extseed[KYBER_SYMBYTES+2];
  int i;

  for(i=0;i<KYBER_SYMBYTES;i++)
    extseed[i] = input[i];
  extseed[i++] = x;
  extseed[i]   = y;
  shake128_absorb(s, extseed, KYBER_SYMBYTES+2);
}

/*************************************************
* Name:        kyber_shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *output:      pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s:            pointer to in/output Keccak state
**************************************************/
void kyber_shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, keccak_state *s)
{
  shake128_squeezeblocks(output, nblocks, s);
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - unsigned char *output:      pointer to output
*              - unsigned long long outlen:  number of requested output bytes
*              - const unsigned char * key:  pointer to the key (of length KYBER_SYMBYTES)
*              - const unsigned char nonce:  single-byte nonce (public PRF input)
**************************************************/
void shake256_prf(unsigned char *output, unsigned long long outlen, const unsigned char *key, const unsigned char nonce)
{
  unsigned char extkey[KYBER_SYMBYTES+1];
  size_t i;

  for(i=0;i<KYBER_SYMBYTES;i++)
    extkey[i] = key[i];
  extkey[i] = nonce;

  shake256(output, outlen, extkey, KYBER_SYMBYTES+1);

}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - unsigned long long outlen:  requested output length in bytes
               - const unsigned char *input: pointer to input
               - unsigned long long inlen:   length of input in bytes
**************************************************/
void shake256(unsigned char *output, unsigned long long outlen,
              const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHAKE256_RATE];
  unsigned long long nblocks = outlen/SHAKE256_RATE;
  size_t i;

  /* Absorb input */
  keccak_absorb(s, SHAKE256_RATE, input, inlen, 0x1F);

  /* Squeeze output */
  keccak_squeezeblocks(output, nblocks, s, SHAKE256_RATE);

  output+=nblocks*SHAKE256_RATE;
  outlen-=nblocks*SHAKE256_RATE;

  if(outlen)
  {
    keccak_squeezeblocks(t, 1, s, SHAKE256_RATE);
    for(i=0;i<outlen;i++)
      output[i] = t[i];
  }
}

#include <stddef.h>
#include "openssl/sha.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "nttru-crypto-stream.h"
#include "nttru-params.h"
#include "nttru-kem.h"
#include "nttru-poly.h"

static const unsigned char n[16] = {0};

int nttru_keygen(nttru_poly *hhat, nttru_poly *fhat, const unsigned char coins[NTTRU_N]) {
  int r;
  nttru_poly f, g;

  nttru_poly_short(&f, coins);
  nttru_poly_short(&g, coins + NTTRU_N/2);
  nttru_poly_triple(&g, &g);
  nttru_poly_triple(&f, &f);
  f.coeffs[0] += 1;
  nttru_poly_ntt(fhat, &f);
  nttru_poly_ntt(&g, &g);
  nttru_poly_freeze(fhat);
  r = nttru_poly_baseinv(&f, fhat);
  nttru_poly_basemul(hhat, &f, &g);
  nttru_poly_freeze(hhat);
  return r;
}

void nttru_encrypt(nttru_poly *chat,
                  const nttru_poly *hhat,
                  const nttru_poly *m,
                  const unsigned char coins[NTTRU_N/2])
{
  nttru_poly r, mhat;

  nttru_poly_short(&r, coins);
  nttru_poly_ntt(&r, &r);
  nttru_poly_ntt(&mhat, m);
  nttru_poly_basemul(chat, &r, hhat);
  nttru_poly_reduce(chat);
  nttru_poly_add(chat, chat, &mhat);
  nttru_poly_freeze(chat);
}

void nttru_decrypt(nttru_poly *m,
                  const nttru_poly *chat,
                  const nttru_poly *fhat)
{
  nttru_poly_basemul(m, chat, fhat);
  nttru_poly_reduce(m);
  nttru_poly_invntt(m, m);
  nttru_poly_crepmod3(m, m);
}


int nttru_crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
  unsigned int i;
  unsigned char coins[NTTRU_N];
  nttru_poly hhat, fhat;

  do {
    RAND_bytes(coins, 32);
    nttru_crypto_stream(coins, NTTRU_N, n, coins);
  } while(nttru_keygen(&hhat, &fhat, coins));

  nttru_poly_pack_uniform(pk, &hhat);
  nttru_poly_pack_uniform(sk, &fhat);

  for(i = 0; i < NTTRU_PUBLICKEYBYTES; ++i)
    sk[i + NTTRU_POLY_PACKED_UNIFORM_BYTES] = pk[i];

  return 0;
}

int nttru_crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk) {
  unsigned int i;
  unsigned char buf[32 + NTTRU_COINBYTES];
  nttru_poly hhat, chat, m;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    return -1;
  }

  // Create secret data from RNG
  RAND_bytes(buf, 32);

  nttru_crypto_stream(buf, NTTRU_N/2, n, buf);
  nttru_poly_short(&m, buf);
  nttru_poly_pack_short(buf, &m);

  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(mdctx, buf, NTTRU_MSGBYTES);
  EVP_DigestFinal_ex(mdctx, buf, NULL);
  EVP_MD_CTX_free(mdctx);

  nttru_crypto_stream(buf + 32, NTTRU_COINBYTES, n, buf + 32);

  nttru_poly_unpack_uniform(&hhat, pk);
  nttru_encrypt(&chat, &hhat, &m, buf + 32);
  nttru_poly_pack_uniform(c, &chat);

  for (i = 0; i < NTTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i];

  return 0;
}

int nttru_crypto_kem_dec(unsigned char *k,
                   const unsigned char *c,
                   const unsigned char *sk)
{
  unsigned int i;
  unsigned char buf[32 + NTTRU_COINBYTES];
  int16_t t;
  int32_t fail;
  nttru_poly m, hhat, chat, fhat;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    return -1;
  }

  nttru_poly_unpack_uniform(&chat, c);
  nttru_poly_unpack_uniform(&fhat, sk);
  nttru_decrypt(&m, &chat, &fhat);

  nttru_poly_pack_short(buf, &m);

  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(mdctx, buf, NTTRU_MSGBYTES);
  EVP_DigestFinal_ex(mdctx, buf, NULL);
  EVP_MD_CTX_free(mdctx);

  nttru_crypto_stream(buf + 32, NTTRU_COINBYTES, n, buf + 32);

  nttru_poly_unpack_uniform(&hhat, sk + NTTRU_POLY_PACKED_UNIFORM_BYTES);
  nttru_encrypt(&fhat, &hhat, &m, buf + 32);

  t = 0;
  for(i = 0; i < NTTRU_N; ++i)
    t |= chat.coeffs[i] ^ fhat.coeffs[i];

  fail = (uint16_t)t;
  fail = (-fail) >> 31;
  for(i = 0; i < NTTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i] & ~(-fail);

  return fail;
}

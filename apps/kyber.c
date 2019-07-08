#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_KYBER
NON_EMPTY_TRANSLATION_UNIT
#else

#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kyber.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum OPTION_choice {
  OPT_ERR = -1,
  OPT_EOF = 0,
  OPT_HELP,
  OPT_INFORM,
  OPT_OUTFORM,
  OPT_ENGINE,
  OPT_IN,
  OPT_OUT,
  OPT_PUBIN,
  OPT_PUBOUT,
  OPT_PASSOUT,
  OPT_PASSIN,
  OPT_KYBERPUBKEY_IN,
  OPT_KYBERPUBKEY_OUT,
  OPT_NOOUT,
  OPT_TEXT,
  OPT_CHECK,
  OPT_CIPHER
} OPTION_CHOICE;

const OPTIONS kyber_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'f', "Input format, one of DER PEM"},
    {"outform", OPT_OUTFORM, 'f', "Output format, one of DER PEM PVK"},
    {"in", OPT_IN, 's', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output a public key"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"KyberPublicKey_in", OPT_KYBERPUBKEY_IN, '-',
     "Input is an KyberPublicKey"},
    {"KyberPublicKey_out", OPT_KYBERPUBKEY_OUT, '-',
     "Output is an KyberPublicKey"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key in text"},
    {"check", OPT_CHECK, '-', "Verify key consistency"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}};

int kyber_main(int argc, char **argv) {
  BIO *in = NULL, *out = NULL;
  ENGINE *e = NULL;
  Kyber *kyber = NULL;
  const EVP_CIPHER *enc = NULL;
  char *infile = NULL, *outfile = NULL, *prog;
  char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
  int i, private = 0;
  int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, check = 0;
  int noout = 0, pubin = 0, pubout = 0, ret = 1;
  OPTION_CHOICE o;

  prog = opt_init(argc, argv, kyber_options);
  while ((o = opt_next()) != OPT_EOF) {
    switch (o) {
    case OPT_EOF:
    case OPT_ERR:
    opthelp:
      BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
      goto end;
    case OPT_HELP:
      opt_help(kyber_options);
      ret = 0;
      goto end;
    case OPT_INFORM:
      if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
        goto opthelp;
      break;
    case OPT_IN:
      infile = opt_arg();
      break;
    case OPT_OUTFORM:
      if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
        goto opthelp;
      break;
    case OPT_OUT:
      outfile = opt_arg();
      break;
    case OPT_PASSIN:
      passinarg = opt_arg();
      break;
    case OPT_PASSOUT:
      passoutarg = opt_arg();
      break;
    case OPT_ENGINE:
      e = setup_engine(opt_arg(), 0);
      break;
    case OPT_PUBIN:
      pubin = 1;
      break;
    case OPT_PUBOUT:
      pubout = 1;
      break;
    case OPT_KYBERPUBKEY_IN:
      pubin = 2;
      break;
    case OPT_KYBERPUBKEY_OUT:
      pubout = 2;
      break;
    case OPT_NOOUT:
      noout = 1;
      break;
    case OPT_TEXT:
      text = 1;
      break;
    case OPT_CHECK:
      check = 1;
      break;
    case OPT_CIPHER:
      if (!opt_cipher(opt_unknown(), &enc))
        goto opthelp;
      break;
    }
  }
  argc = opt_num_rest();
  if (argc != 0)
    goto opthelp;

private
  = (text && !pubin) || (!pubout && !noout) ? 1 : 0;

  if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
    BIO_printf(bio_err, "Error getting passwords\n");
    goto end;
  }
  if (check && pubin) {
    BIO_printf(bio_err, "Only private keys can be checked\n");
    goto end;
  }

  if (informat != FORMAT_ENGINE) {
    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
      goto end;
  }

  BIO_printf(bio_err, "read Kyber key\n");
  if (informat == FORMAT_ASN1) {
    if (pubin)
      kyber = d2i_Kyber_PUBKEY_bio(in, NULL);
    else
      kyber = d2i_KyberPrivateKey_bio(in, NULL);
  } else if (informat == FORMAT_ENGINE) {
    EVP_PKEY *pkey;
    if (pubin)
      pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key");
    else
      pkey = load_key(infile, informat, 1, passin, e, "Private Key");
    if (pkey != NULL) {
      kyber = EVP_PKEY_get1_Kyber(pkey);
      EVP_PKEY_free(pkey);
    }
  } else {
    if (pubin)
      kyber = PEM_read_bio_KYBER_PUBKEY(in, NULL, NULL, NULL);
    else
      kyber = PEM_read_bio_KyberPrivateKey(in, NULL, NULL, passin);
  }

  if (kyber == NULL) {
    ERR_print_errors(bio_err);
    goto end;
  }

  out = bio_open_owner(outfile, outformat, private);
  if (out == NULL)
    goto end;

  if (text) {
    assert(pubin || private);
    if (!kyber_print(out, kyber, 0)) {
      perror(outfile);
      ERR_print_errors(bio_err);
      goto end;
    }
  }

  if (check) {
    int r = kyber_check_key_ex(kyber);

    if (r == 1) {
      BIO_printf(out, "Kyber key ok\n");
    } else if (r == 0) {
      unsigned long err;

      while ((err = ERR_peek_error()) != 0 &&
             ERR_GET_LIB(err) == ERR_LIB_KYBER &&
             ERR_GET_FUNC(err) == KYBER_F_KYBER_CHECK_KEY_EX &&
             ERR_GET_REASON(err) != ERR_R_MALLOC_FAILURE) {
        BIO_printf(out, "Kyber key error: %s\n", ERR_reason_error_string(err));
        ERR_get_error(); /* remove err from error stack */
      }
    } else if (r == -1) {
      ERR_print_errors(bio_err);
      goto end;
    }
  }

  if (noout) {
    ret = 0;
    goto end;
  }
  BIO_printf(bio_err, "writing Kyber key\n");
  if (outformat == FORMAT_ASN1) {
    if (pubout || pubin) {
      if (pubout == 2)
        i = i2d_KyberPublicKey_bio(out, kyber);
      else
        i = i2d_Kyber_PUBKEY_bio(out, kyber);
    } else {
      assert(private);
      i = i2d_KyberPrivateKey_bio(out, kyber);
    }
  } else if (outformat == FORMAT_PEM) {
    if (pubout || pubin) {
      if (pubout == 2)
        i = PEM_write_bio_KyberPublicKey(out, kyber);
      else
        i = PEM_write_bio_KYBER_PUBKEY(out, kyber);
    } else {
      assert(private);
      i = PEM_write_bio_KyberPrivateKey(out, kyber, enc, NULL, 0, NULL,
                                        passout);
    }
  } else {
    BIO_printf(bio_err, "bad output format specified for outfile\n");
    goto end;
  }
  if (i <= 0) {
    BIO_printf(bio_err, "unable to write key\n");
    ERR_print_errors(bio_err);
  } else {
    ret = 0;
  }
end:
  release_engine(e);
  BIO_free_all(out);
  kyber_free(kyber);
  OPENSSL_free(passin);
  OPENSSL_free(passout);
  return ret;
}
#endif

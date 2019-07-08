#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_DILITHIUM
NON_EMPTY_TRANSLATION_UNIT
#else

#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/dilithium.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef enum OPTION_choice {
  OPT_ERR = -1,
  OPT_EOF = 0,
  OPT_HELP,
  OPT_ENGINE,
  OPT_OUT,
  OPT_PASSOUT,
  OPT_CIPHER,
  OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS gendilithium_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output the key to specified file"},
    OPT_R_OPTIONS,
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"", OPT_CIPHER, '-', "Encrypt the output with any supported cipher"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}};

int gendilithium_main(int argc, char **argv) {
  ENGINE *eng = NULL;
  BIO *out = NULL;
  Dilithium *dilithium = NULL;
  const EVP_CIPHER *enc = NULL;
  int ret = 1, private = 0, mode = 2;
  char *outfile = NULL, *passoutarg = NULL, *passout = NULL;
  char *prog;
  OPTION_CHOICE o;

  prog = opt_init(argc, argv, gendilithium_options);
  while ((o = opt_next()) != OPT_EOF) {
    switch (o) {
    case OPT_EOF:
    case OPT_ERR:
    opthelp:
      BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
      goto end;
    case OPT_HELP:
      ret = 0;
      opt_help(gendilithium_options);
      goto end;
    case OPT_OUT:
      outfile = opt_arg();
      break;
    case OPT_ENGINE:
      eng = setup_engine(opt_arg(), 0);
      break;
    case OPT_PASSOUT:
      passoutarg = opt_arg();
      break;
    case OPT_CIPHER:
      if (!opt_cipher(opt_unknown(), &enc))
        goto end;
      break;
    case OPT_R_CASES:
      if (!opt_rand(o))
        goto end;
      break;
    }
  }
  argc = opt_num_rest();
  argv = opt_rest();

  if (argc == 1) {
    if (!opt_int(argv[0], &mode) || mode <= 0)
      goto end;
  } else if (argc > 0) {
    BIO_printf(bio_err, "Extra arguments given.\n");
    goto opthelp;
  }

private
  = 1;
  if (!app_passwd(NULL, passoutarg, NULL, &passout)) {
    BIO_printf(bio_err, "Error getting password\n");
    goto end;
  }

  out = bio_open_owner(outfile, FORMAT_PEM, private);
  if (out == NULL)
    goto end;

  BIO_printf(bio_err, "Generating Dilithium private key, %d mode\n", mode);
  dilithium = eng ? dilithium_new_method(eng) : dilithium_new();
  if (dilithium == NULL)
    goto end;

  if (!dilithium_generate_key_ex(dilithium, mode))
    goto end;

  assert(private);
  if (!PEM_write_bio_DilithiumPrivateKey(out, dilithium, enc, NULL, 0, NULL,
                                         passout))
    goto end;

  ret = 0;
end:
  dilithium_free(dilithium);
  BIO_free_all(out);
  release_engine(eng);
  OPENSSL_free(passout);
  if (ret != 0)
    ERR_print_errors(bio_err);
  return ret;
}
#endif

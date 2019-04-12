#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_KYBER
NON_EMPTY_TRANSLATION_UNIT
#else

# include "apps.h"
# include "progs.h"
# include <string.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/kyber.h>

# define KYBER_ENCRYPT     3
# define KYBER_DECRYPT     4

# define KEY_PRIVKEY     1
# define KEY_PUBKEY      2
# define KEY_CERT        3

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_IN, OPT_OUT, OPT_ASN1PARSE, OPT_HEXDUMP,
    OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_PUBIN, OPT_CERTIN, OPT_INKEY, OPT_PASSIN, OPT_KEYFORM,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS kyberutl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"inkey", OPT_INKEY, 's', "Input key"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
    {"pubin", OPT_PUBIN, '-', "Input is an Kyber public"},
    {"certin", OPT_CERTIN, '-', "Input is a cert carrying an Kyber public key"},
    {"asn1parse", OPT_ASN1PARSE, '-',
     "Run output through asn1parse; useful with -verify"},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"rev", OPT_REV, '-', "Reverse the order of the input buffer"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt with private key"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    OPT_R_OPTIONS,
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int kyberutl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    Kyber *kyber = NULL;
    X509 *x;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL;
    char *passinarg = NULL, *passin = NULL, *prog;
    char kyber_mode = KYBER_ENCRYPT, key_type = KEY_PRIVKEY;
    unsigned char *kyber_in = NULL, *kyber_out = NULL;
    int kyber_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
    int kyber_outlen = 0, hexdump = 0, asn1parse = 0, need_priv = 0, rev = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, kyberutl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(kyberutl_options);
            ret = 0;
            goto end;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_ASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_ENCRYPT:
            kyber_mode = KYBER_ENCRYPT;
            break;
        case OPT_DECRYPT:
            kyber_mode = KYBER_DECRYPT;
            need_priv = 1;
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_INKEY:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (need_priv && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyformat, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyformat, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyformat, "Certificate");
        if (x) {
            pkey = X509_get_pubkey(x);
            X509_free(x);
        }
        break;
    }

    if (pkey == NULL)
        return 1;

    kyber = EVP_PKEY_get1_Kyber(pkey);
    EVP_PKEY_free(pkey);

    if (kyber == NULL) {
        BIO_printf(bio_err, "Error getting Kyber key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    in = bio_open_default(infile, 'r', FORMAT_BINARY);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    // TODO: Figure out a way to return a key size
    keysize = 16000;

    kyber_in = app_malloc(keysize * 2, "hold kyber key");
    kyber_out = app_malloc(keysize, "output kyber key");

    /* Read the input data */
    kyber_inlen = BIO_read(in, kyber_in, keysize * 2);
    if (kyber_inlen < 0) {
        BIO_printf(bio_err, "Error reading input Data\n");
        goto end;
    }
    if (rev) {
        int i;
        unsigned char ctmp;
        for (i = 0; i < kyber_inlen / 2; i++) {
            ctmp = kyber_in[i];
            kyber_in[i] = kyber_in[kyber_inlen - 1 - i];
            kyber_in[kyber_inlen - 1 - i] = ctmp;
        }
    }
    switch (kyber_mode) {

    case KYBER_ENCRYPT:
        kyber_outlen = kyber_public_encrypt(kyber_inlen, kyber_in, kyber_out, kyber);
        break;

    case KYBER_DECRYPT:
        kyber_outlen =
            kyber_private_decrypt(kyber_inlen, kyber_in, kyber_out, kyber);
        break;
    }

    if (kyber_outlen < 0) {
        BIO_printf(bio_err, "Kyber operation error\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!ASN1_parse_dump(out, kyber_out, kyber_outlen, 1, -1)) {
            ERR_print_errors(bio_err);
        }
    } else if (hexdump) {
        BIO_dump(out, (char *)kyber_out, kyber_outlen);
    } else {
        BIO_write(out, kyber_out, kyber_outlen);
    }
 end:
    kyber_free(kyber);
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    OPENSSL_free(kyber_in);
    OPENSSL_free(kyber_out);
    OPENSSL_free(passin);
    return ret;
}
#endif

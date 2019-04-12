#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include <stdint.h>
#include "kyber_poly.h"

void kyber_cbd(kyber_poly *r, const unsigned char *buf, const uint64_t kyber_eta);

#endif

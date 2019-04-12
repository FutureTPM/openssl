#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>

void kyber_ntt(uint16_t* poly);
void kyber_invntt(uint16_t* poly);

#endif

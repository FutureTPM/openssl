#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>

uint16_t kyber_freeze(uint16_t x);

uint16_t kyber_montgomery_reduce(uint32_t a);

uint16_t kyber_barrett_reduce(uint16_t a);

#endif
#include "kyber-reduce.h"
#include "kyber-params.h"

static const uint32_t kyber_qinv = 62209;

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q,
*              where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced; has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
int16_t kyber_montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = a * kyber_qinv;
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return t;
}


/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,11768}
*
* Arguments:   - uint16_t a: input unsigned integer to be reduced
*
* Returns:     unsigned integer in {0,...,11768} congruent to a modulo q.
**************************************************/
int16_t kyber_barrett_reduce(int16_t a) {
    int32_t t;
    const int32_t v = (1U << 26)/KYBER_Q + 1;

    t = v*a;
    t >>= 26;
    t *= KYBER_Q;
    return a - t;
}

/*************************************************
* Name:        csubq
*
* Description: Conditionallly subtract q
*
* Arguments:   - int16_t x: input integer
*
* Returns:     a - q if a >= q, else a
**************************************************/
int16_t kyber_csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}
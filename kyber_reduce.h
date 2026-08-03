#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>
#include "kyber_params.h"

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

#define kyber_montgomery_reduce KYBER_NAMESPACE(kyber_montgomery_reduce)
int16_t kyber_montgomery_reduce(int32_t a);

#define kyber_barrett_reduce KYBER_NAMESPACE(kyber_barrett_reduce)
int16_t kyber_barrett_reduce(int16_t a);

#endif

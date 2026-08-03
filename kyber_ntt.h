#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>
#include "kyber_params.h"

#define kyber_zetas KYBER_NAMESPACE(kyber_zetas)
extern const int16_t kyber_zetas[128];

#define kyber_ntt KYBER_NAMESPACE(kyber_ntt)
void kyber_ntt(int16_t poly[256]);

#define kyber_invntt KYBER_NAMESPACE(kyber_invntt)
void kyber_invntt(int16_t poly[256]);

#define kyber_basemul KYBER_NAMESPACE(kyber_basemul)
void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif

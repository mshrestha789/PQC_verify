#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include <stdint.h>
#include "kyber_params.h"
#include "kyber_poly.h"

typedef struct{
  kyber_poly vec[KYBER_K];
} kyber_polyvec;

#define kyber_polyvec_compress KYBER_NAMESPACE(kyber_polyvec_compress)
void kyber_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const kyber_polyvec *a);
#define kyber_polyvec_decompress KYBER_NAMESPACE(kyber_polyvec_decompress)
void kyber_polyvec_decompress(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

#define kyber_polyvec_tobytes KYBER_NAMESPACE(kyber_polyvec_tobytes)
void kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const kyber_polyvec *a);
#define kyber_polyvec_frombytes KYBER_NAMESPACE(kyber_polyvec_frombytes)
void kyber_polyvec_frombytes(kyber_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

#define kyber_polyvec_ntt KYBER_NAMESPACE(kyber_polyvec_ntt)
void kyber_polyvec_ntt(kyber_polyvec *r);
#define kyber_polyvec_invntt_tomont KYBER_NAMESPACE(kyber_polyvec_invntt_tomont)
void kyber_polyvec_invntt_tomont(kyber_polyvec *r);

#define kyber_polyvec_basemul_acc_montgomery KYBER_NAMESPACE(kyber_polyvec_basemul_acc_montgomery)
void kyber_polyvec_basemul_acc_montgomery(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b);

#define kyber_polyvec_reduce KYBER_NAMESPACE(kyber_polyvec_reduce)
void kyber_polyvec_reduce(kyber_polyvec *r);

#define kyber_polyvec_add KYBER_NAMESPACE(kyber_polyvec_add)
void kyber_polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b);

#endif

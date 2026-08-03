#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include "kyber_params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} kyber_poly;

#define kyber_poly_compress KYBER_NAMESPACE(kyber_poly_compress)
void kyber_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const kyber_poly *a);
#define kyber_poly_decompress KYBER_NAMESPACE(kyber_poly_decompress)
void kyber_poly_decompress(kyber_poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

#define kyber_poly_tobytes KYBER_NAMESPACE(kyber_poly_tobytes)
void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const kyber_poly *a);
#define kyber_poly_frombytes KYBER_NAMESPACE(kyber_poly_frombytes)
void kyber_poly_frombytes(kyber_poly *r, const uint8_t a[KYBER_POLYBYTES]);

#define kyber_poly_frommsg KYBER_NAMESPACE(kyber_poly_frommsg)
void kyber_poly_frommsg(kyber_poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
#define kyber_poly_tomsg KYBER_NAMESPACE(kyber_poly_tomsg)
void kyber_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const kyber_poly *r);

#define kyber_poly_getnoise_eta1 KYBER_NAMESPACE(kyber_poly_getnoise_eta1)
void kyber_poly_getnoise_eta1(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define kyber_poly_getnoise_eta2 KYBER_NAMESPACE(kyber_poly_getnoise_eta2)
void kyber_poly_getnoise_eta2(kyber_poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define kyber_poly_ntt KYBER_NAMESPACE(kyber_poly_ntt)
void kyber_poly_ntt(kyber_poly *r);
#define kyber_poly_invntt_tomont KYBER_NAMESPACE(kyber_poly_invntt_tomont)
void kyber_poly_invntt_tomont(kyber_poly *r);
#define kyber_poly_basemul_montgomery KYBER_NAMESPACE(kyber_poly_basemul_montgomery)
void kyber_poly_basemul_montgomery(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);
#define kyber_poly_tomont KYBER_NAMESPACE(kyber_poly_tomont)
void kyber_poly_tomont(kyber_poly *r);

#define kyber_poly_reduce KYBER_NAMESPACE(kyber_poly_reduce)
void kyber_poly_reduce(kyber_poly *r);

#define kyber_poly_add KYBER_NAMESPACE(kyber_poly_add)
void kyber_poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);
#define kyber_poly_sub KYBER_NAMESPACE(kyber_poly_sub)
void kyber_poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);

#endif

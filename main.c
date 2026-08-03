#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "params.h"
#include "sign.h"
#include "kyber_api.h"

#define NONCE_LEN 12
#define TAG_LEN   16
#define KYBER_CT_LEN pqcrystals_kyber512_ref_CIPHERTEXTBYTES
#define SS_LEN pqcrystals_kyber512_ref_BYTES

#define SK_FILE "kyber_sk.bin"

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

// Convert hex char to byte
static uint8_t hex_to_byte(const char* hex) {
    uint8_t val = 0;
    for (int i = 0; i < 2; ++i) {
        val <<= 4;
        if (hex[i] >= '0' && hex[i] <= '9') val |= hex[i] - '0';
        else if (hex[i] >= 'A' && hex[i] <= 'F') val |= hex[i] - 'A' + 10;
        else if (hex[i] >= 'a' && hex[i] <= 'f') val |= hex[i] - 'a' + 10;
    }
    return val;
}

// Convert hex string to byte array
static int hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = hex_to_byte(&hex[i * 2]);
    }
    return 0;
}

DLL_EXPORT
int verify_and_extract(
    const char* msg_hex,
    const char* pk_hex,
    const char* sig_hex,
    uint8_t* out_ss,          // 32 bytes
    uint8_t* out_nonce,       // 12 bytes
    uint8_t* out_tag,         // 16 bytes
    uint8_t* out_ciphertext,  // variable
    size_t* out_ciphertext_len
) {
    size_t msg_len = strlen(msg_hex) / 2;
    if (msg_len < KYBER_CT_LEN + NONCE_LEN + TAG_LEN)
        return -1;  // Too short

    // Allocate and parse binary message
    uint8_t* msg_bin = malloc(msg_len);
    if (!msg_bin) return -2;

    hex_to_bytes(msg_hex, msg_bin, msg_len);

    const uint8_t* kyber_ct = msg_bin;
    const uint8_t* nonce = msg_bin + KYBER_CT_LEN;
    const uint8_t* tag = nonce + NONCE_LEN;
    const uint8_t* ciphertext = tag + TAG_LEN;
    size_t ciphertext_len = msg_len - (KYBER_CT_LEN + NONCE_LEN + TAG_LEN);

    // Verify signature
    size_t sig_len = CRYPTO_BYTES;
    size_t pk_len = CRYPTO_PUBLICKEYBYTES;
    uint8_t sig[CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t* msg = malloc(msg_len);

    hex_to_bytes(sig_hex, sig, sig_len);
    hex_to_bytes(pk_hex, pk, pk_len);
    hex_to_bytes(msg_hex, msg, msg_len);

	// Verify Dilithium signature
    int result = crypto_sign_verify(sig, CRYPTO_BYTES, msg, msg_len, NULL, 0, pk);
    if( result != 0) {
        free(msg_bin);
        free(msg);
        return -3; // signature verification failed
	}
    free(msg);


   
    // Load Kyber secret key
    uint8_t sk[pqcrystals_kyber512_ref_SECRETKEYBYTES];
    FILE* fsk = fopen(SK_FILE, "rb");
    if (!fsk || fread(sk, 1, sizeof(sk), fsk) != sizeof(sk)) {
        free(msg_bin);
        if (fsk) fclose(fsk);
        return -4; // failed to load kyber sk
    }
    fclose(fsk);

    // Decapsulate shared secret
    if (pqcrystals_kyber512_ref_dec(out_ss, kyber_ct, sk) != 0) {
        free(msg_bin);
        return -5; // decapsulation failed
    }

    // Output nonce, tag, ciphertext
    memcpy(out_nonce, nonce, NONCE_LEN);
    memcpy(out_tag, tag, TAG_LEN);
    memcpy(out_ciphertext, ciphertext, ciphertext_len);
    *out_ciphertext_len = ciphertext_len;

    free(msg_bin);
    return 0;  // success
}

// Note: This code assumes that the Kyber secret key is stored in a file named "kyber_sk.bin".
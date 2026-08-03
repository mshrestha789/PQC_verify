#if 0
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "kyber_api.h"

#define KYBER_CT_LEN pqcrystals_kyber512_ref_CIPHERTEXTBYTES
#define KYBER_SK_LEN pqcrystals_kyber512_ref_SECRETKEYBYTES
#define SHARED_SECRET_LEN pqcrystals_kyber512_ref_BYTES

#define NONCE_LEN 12
#define TAG_LEN 16
#define SK_FILE "kyber_sk.bin"

// Converts a hex string to bytes
void hex_to_bytes(const char* hex, uint8_t* out, size_t len_bytes) {
    for (size_t i = 0; i < len_bytes; ++i) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
}

// Pretty hex printer
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("\n");
}

void print_hex_array(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("0x%02X", data[i]);
        if (i < len - 1) printf(", ");
        if ((i + 1) % 8 == 0) printf("\n");
    }
    if (len % 8 != 0) printf("\n");
    printf("\n");
}


int main() {
    const char* hex_message =
        "BA2D8E792BDD501360613911B4DDD60E3BAAC65F8F3ECEF6769134BB43C74D4B2A5935CEE1D5DF4BC8C2B24D2476FFF227BD79CB3D6BAFC7281979873FD9815A50F6E559644E6F0191A6A12C61D1819D5561FABA5DC08FF7EA34FB8D31C3BC358C9C84AC3CD5F665505EE2FA343EC28A4CD8E48CE1C078B164E37E516FAEC0868987E37CD7DDB95A15FBAE4E1D8F6501494D578222464E073EB2D002B0E4F92E00454AE97E77F09967AD509EB72EEF2F8F76D33A508E260AA88A4C629E7932409B78469CB1C7DEEF5464C124969886FA29F7E7C73EF07A932D14B773D50EDF509F37F2F26F1FCEEB637D36CDA3CB1F0648677B0787C1E3656F25DFC19B89681A1FFAA46203800D4D347D4D5C920C6EE2E69A0E2DFEBD24902C5D7DC2E696F04E0C0395FB424C93090FABFA3BD4499FD797AB4C4AE7D02F88F3F3C97E81812F9F28BC1F4E3352B585FA2FE652C19B641EC879CB4E84CA3FC828EC277C174DB50C74000F13127046FC4C96CFEABEDD0E3C46241C9CFD2AD2D71369BFE57E7C82EE7604CDC70E6E04E244A68A29A21CFEB95C54143A6E617FDA5ACF8530B1B10FCFC0D91D2C25900955ACC2B9F50BD54B993B6A546050DC9A5CA99B221C08C5AC2D9D508BFACCBB28A62D9FE02260F33D1B561253782E1A91B0638F77958001CF11D70569E67DB4414FE6FFE637DC608C4CD392A307827F58545F4A49404C091BBD88C7A0AB6F296DB695202363DF0F4DA19B7E478ED23AF06A00F6FC1ACA6E3CB9545673647972C572BD7853CB0655722C91FC10F33DB85D136F42F0A1F5AE589D66357128405C96029DE746B33624C1D89EE8A71075A9FC30CC0917261B94166F58E95786858675C95132957537815F933DA73C2A8034821BE7E23FF78E75D24F54F23A4FE939202DD3420C334AAC672C630E344E27278B1A9EE546F1DFBBAFBA76288CAFF3F08F0943D0BB43EA7E5DC3618243A1A384C708EFBE52A72510EA405338E9A81FB1CF7FDD59E28EA8AB7D36E1A2CFE9D37D022233C2176811819E7B9F8C4085C2B0A8E7FA92BD3EE4048918DCE31ADDF9435DEDA946DD1449B48EAF79EC9197E0AC70CB11FAD16DB3F33CC3F427DD7BAF390721F73084B774775F7331028284706F594C1B6283141A483768D07639A7FA607000AE1B9F7212E73BB2C1A3B124B15F01C7A5ACB58D65C9530D24F305B574723B1782386E2264B7B590BFA190119F3EE677200FB94DDD0F2DADCA25FEFDDFDE95C04FFCCFE17F16738EE34104820F603251F5B5C8B6DD20A0DDB93206E43FBB87C1B5029452C1B25615440DFFFC69";

    size_t hex_len = strlen(hex_message);
    size_t total_len = hex_len / 2;
    uint8_t* buffer = malloc(total_len);
    if (!buffer) {
        printf("Memory allocation failed\n");
        return 1;
    }

    hex_to_bytes(hex_message, buffer, total_len);

    if (total_len < KYBER_CT_LEN + NONCE_LEN + TAG_LEN) {
        printf("Message too short\n");
        free(buffer);
        return 1;
    }

    const uint8_t* ct = buffer;
    const uint8_t* nonce = ct + KYBER_CT_LEN;
    const uint8_t* tag = nonce + NONCE_LEN;
    const uint8_t* ciphertext = tag + TAG_LEN;
    size_t ciphertext_len = total_len - (KYBER_CT_LEN + NONCE_LEN + TAG_LEN);

    print_hex("Kyber Ciphertext", ct, KYBER_CT_LEN);
    print_hex("Nonce", nonce, NONCE_LEN);
    print_hex("Tag", tag, TAG_LEN);
    print_hex("Encrypted Payload", ciphertext, ciphertext_len);

    
    
    print_hex_array("Nonce", nonce, NONCE_LEN);
    print_hex_array("Tag", tag, TAG_LEN);
    print_hex_array("Encrypted Payload", ciphertext, ciphertext_len);

    // Load secret key
    uint8_t sk[KYBER_SK_LEN];
    FILE* fp = fopen(SK_FILE, "rb");
    if (!fp || fread(sk, 1, KYBER_SK_LEN, fp) != KYBER_SK_LEN) {
        fprintf(stderr, "Failed to read secret key from '%s'\n", SK_FILE);
        free(buffer);
        return 1;
    }
    fclose(fp);

    // Kyber decapsulation
    uint8_t ss[SHARED_SECRET_LEN];
    if (pqcrystals_kyber512_ref_dec(ss, ct, sk) != 0) {
        fprintf(stderr, "Kyber decapsulation failed\n");
        free(buffer);
        return 1;
    }

    print_hex("Decapsulated Shared Secret", ss, SHARED_SECRET_LEN);
    print_hex_array("Decapsulated Shared Secret", ss, SHARED_SECRET_LEN);

    free(buffer);
    return 0;
}


#endif
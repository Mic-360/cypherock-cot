#include <stdint.h>
#include <stddef.h>

/* MSVC __builtin_clz replacement */
#ifdef _MSC_VER
#include <intrin.h>
int __builtin_clz(unsigned int x) {
    unsigned long index;
    _BitScanReverse(&index, x);
    return 31 - (int)index;
}
#endif

size_t address_prefix_bytes_len(uint32_t address_type) {
    (void)address_type;
    return 0;
}

void address_write_prefix_bytes(uint32_t address_type, uint8_t *out) {
    (void)address_type;
    (void)out;
}

uint32_t address_check_prefix(const uint8_t *addr, uint32_t address_type) {
    (void)addr;
    (void)address_type;
    return 0;
}

int base58_encode_check(const uint8_t *data, int datalen,
                        char *str, int strsize) {
    (void)data; (void)datalen; (void)str; (void)strsize;
    return 0;
}

int base58_decode_check(const char *str, uint8_t *data, int datalen) {
    (void)str; (void)data; (void)datalen;
    return 0;
}

typedef struct {
    uint8_t dummy[256];
} rfc6979_state;

void init_rfc6979(const uint8_t *priv_key, const uint8_t *hash,
                  rfc6979_state *state) {
    (void)priv_key; (void)hash; (void)state;
}

void generate_k_rfc6979(uint8_t *k, rfc6979_state *state) {
    (void)k; (void)state;
}

typedef struct {
    uint8_t dummy[512];
} Hasher;

void hasher_Init(Hasher *hasher, int type) {
    (void)hasher; (void)type;
}

void hasher_Update(Hasher *hasher, const uint8_t *data, size_t length) {
    (void)hasher; (void)data; (void)length;
}

void hasher_Final(Hasher *hasher, uint8_t *hash) {
    (void)hasher; (void)hash;
}

void hasher_Raw(int type, const uint8_t *data, size_t length, uint8_t *hash) {
    (void)type; (void)data; (void)length; (void)hash;
}

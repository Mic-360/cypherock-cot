/**
 * rand_win.c — windows random
 * replaces weak attributes because msvc doesn't like
 */

#ifdef _WIN32
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

uint32_t random32(void) {
    uint32_t value = 0;
    BCryptGenRandom(NULL, (PUCHAR)&value, sizeof(value),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return value;
}

void random_buffer(uint8_t *buf, size_t len) {
    BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#else

/* non-windows fallback 
 * use ubuntu or don't blame me coz my wsl has ubuntu and i tested only on that
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

uint32_t random32(void) {
    uint32_t value = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(&value, sizeof(value), 1, f);
        fclose(f);
    }
    return value;
}

void random_buffer(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    }
}
#endif

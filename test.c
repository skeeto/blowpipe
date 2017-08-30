#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vectors2.h"
#include "blowfish.h"

static void
print_bytes(void *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x%c", ((unsigned char *)buf)[i], " \n"[i == len - 1]);
}

static int
verify(void *a, void *b, size_t len)
{
    if (memcmp(a, b, len) != 0) {
        printf("expect: ");
        print_bytes(a, len);
        printf("actual: ");
        print_bytes(b, len);
        return 1;
    }
    return 0;
}

static void
spill(uint8_t *p, uint32_t l, uint32_t r)
{
    p[0] = (uint8_t)(l >> 24);
    p[1] = (uint8_t)(l >> 16);
    p[2] = (uint8_t)(l >>  8);
    p[3] = (uint8_t)(l >>  0);
    p[4] = (uint8_t)(r >> 24);
    p[5] = (uint8_t)(r >> 16);
    p[6] = (uint8_t)(r >>  8);
    p[7] = (uint8_t)(r >>  0);
}

int
main(void)
{
    int failures = 0;

    {
        /* Test simple string encryption / decryption */
        struct blowfish ctx[1];
        char key[] = "foobar";
        char plain[] = "blowfishdeadbeef";
        char cipher[16];
        char output[16];
        blowfish_init(ctx, key, sizeof(key) - 1);
        blowfish_encrypt(ctx, cipher, plain, 16);
        blowfish_decrypt(ctx, output, cipher, 16);
        failures += verify(plain, output, 16);
    }

    for (int i = 0; i < NUM_VARIABLE_KEY_TESTS; i++) {
        struct blowfish ctx[1];
        blowfish_init(ctx, variable_key[i], 8);

        uint8_t buf[8];
        spill(buf, plaintext_l[i], plaintext_r[i]);
        blowfish_encrypt(ctx, buf, buf, 8);

        uint8_t ver[8];
        spill(ver, ciphertext_l[i], ciphertext_r[i]);
        failures += verify(ver, buf, 8);
    }

    for (int z = 1; z <= (int)sizeof(set_key); z++) {
        struct blowfish ctx[1];
        blowfish_init(ctx, set_key, z);

        uint8_t buf[8];
        uint8_t *plain = variable_key[NUM_VARIABLE_KEY_TESTS - 1];
        blowfish_encrypt(ctx, buf, plain, 8);

        uint8_t ver[8];
        int i = NUM_VARIABLE_KEY_TESTS + (int)z - 1;
        spill(ver, ciphertext_l[i], ciphertext_r[i]);
        failures += verify(ver, buf, 8);
    }

    printf("%d failures\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

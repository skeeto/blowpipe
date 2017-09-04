#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vectors2.h"
#include "../blowfish.h"

#define NUM_BCRYPT_VECTORS (sizeof(bcrypt_vectors)/sizeof(*bcrypt_vectors)/2)
static const char bcrypt_vectors[][64] = {
    "twist",  "$2a$04$mlr.PoDP3w4SzMh8A/td4O2LE5lJcM2/JSPEwYH0wXmT/Ai.Ip3GG",
    "sector", "$2a$04$4u14y0XgEKWfE2yS.VF6JuZhzI2JAcIsSM0ukKuSeFZDPH2Qfp2Ku",
    "cue",    "$2a$05$B8Ld4qjLv/sMgtkdO6o8iO7Sm61jDwADJ9Y8fTXZyQqoG1qftwF82",
    "fading", "$2a$05$5d6JDfbFA3AZSBJpZmCcVuJQjo7QSgzePx3nS3PqTTsG.aqoDUkPW",
    "wedge",  "$2a$06$LtzByA9pukm5I9XbW.6t6eZy3Qkg1pB17IuzfTfSCsky2X5eoFMua",
    "owns",   "$2a$06$8wgs0GP1l0uT294gIj5STeFhpFAXsdChz8bdypccbpAQbevxWne9K",
    "cause",  "$2a$07$IEtr9PejuMM8wSZpvQ4WL.rEdfz.2Y0R6ELEi2RaVKWXM5HbhUujq",
    "visual", "$2a$07$xXB.ianZO3Fzo4oG28uh1e.MoLZVezlYTOcm7kOKiIfp4L0MQFEBO",
    "thumbs", "$2a$08$vWI4Y9ApphxiDVlB.9wRYeoOlqEQa2q3wuQ8gQbhWFm5THOVYUc4K",
    "stare",  "$2a$08$OEB986UEwkJLIw7SdoXKju/lgW7j/bVjsVaaaVEo461KdyUMxT/AO",
    "corpse", "$2a$09$MEKwC6Me6/hwiRMLoICLLOkIYIm8InZA39VlMRC0o9yHR1dW7P5q.",
    "taste",  "$2a$09$f0rzicUe7fceAk7BcbEgZegPcX5fyAV0YmSJsGT0cgAoTJaJL9LBa",
    "loves",  "$2a$10$WRpreT7IpmlwVcAUJWHPhea6nb2cEKMdxDdDbuNNJORVLuRNA4ofi",
    "slices", "$2a$10$JL73nWnZVBXZsV9/DZDQruS27YKRk.NnlqM0WJ8evHOcNfRZR67i6",
    "roots",  "$2a$11$XRKrSKrCuUKnb5sllKpJ9.VscoH9O7ppsPeABflG20iPRGoKozv7a",
    "own",    "$2a$11$P.Sp8zWnDMjRkSH5uc5./eVg4aZyTPajJGdGg.rs3/UX.1/dfFwsm"
};

static const char base64[] = {
    '.', '/', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9',
};

static const unsigned char index64[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x40, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3e, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
    0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static void
b64encode(char *dst, const void *src, size_t len)
{
    int ocount = 0;
    unsigned overflow = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned c = ((unsigned char *)src)[i];
        overflow = c | (overflow << 8);
        ocount += 8;
        while (ocount >= 6) {
            *dst++ = base64[(overflow >> (ocount - 6)) & 0x3f];
            ocount -= 6;
        }
    }
    if (ocount > 0)
        *dst++ = base64[(overflow << (6 - ocount)) & 0x3f];
    *dst = 0;
}

static void
b64decode(void *dst, const char *src)
{
    int c;
    int ocount = 0;
    unsigned overflow = 0;
    unsigned char *p = dst;
    while ((c = *src++)) {
        c = index64[c];
        overflow = (overflow << 6) | c;
        ocount += 6;
        while (ocount >= 8) {
            *p++ = (overflow >> (ocount - 8)) & 0xff;
            ocount -= 8;
        }
    }
}

struct bcrypt {
    uint8_t salt[BLOWFISH_SALT_LENGTH];
    uint8_t digest[BLOWFISH_DIGEST_LENGTH];
    int cost;
};

static void
bcrypt_decode(struct bcrypt *bc, const char *str)
{
    char salt[32];
    memcpy(salt, str + 7, 31);
    salt[31] = 0;
    b64decode(bc->salt, salt);
    b64decode(bc->digest, str + 28);
    bc->cost = (str[4] - '0') * 10 + str[5] - '0';
}

static void
bcrypt_encode(struct bcrypt *bc, char *str)
{
    str[0] = '$';
    str[1] = '2';
    str[2] = 'a';
    str[3] = '$';
    str[4] = '0' + (bc->cost / 10);
    str[5] = '0' + (bc->cost % 10);
    str[6] = '$';
    b64encode(str + 7, bc->salt, BLOWFISH_SALT_LENGTH);
    b64encode(str + 29, bc->digest, BLOWFISH_DIGEST_LENGTH - 1);
}

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

    /* Test bcrypt */
    for (size_t i = 0; i < NUM_BCRYPT_VECTORS; i++) {
        struct bcrypt bc[1];
        const char *pwd = bcrypt_vectors[i * 2 + 0];
        int pwdlen = strlen(pwd) + 1;
        const char *expect = bcrypt_vectors[i * 2 + 1];

        bcrypt_decode(bc, expect);
        memset(bc->digest, 0x5a, sizeof(bc->digest));
        blowfish_bcrypt(bc->digest, pwd, pwdlen, bc->salt, bc->cost);

        char actual[64];
        bcrypt_encode(bc, actual);
        if (strcmp(expect, actual) != 0) {
            printf("expect: %s\n", expect);
            printf("actual: %s\n", actual);
            failures++;
        }
    }

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

/* C99 Blowfish implementation
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

#define BLOWFISH_BLOCK_LENGTH    8
#define BLOWFISH_SALT_LENGTH     16
#define BLOWFISH_DIGEST_LENGTH   24
#define BLOWFISH_MAX_KEY_LENGTH  72
#define BLOWFISH_MAX_COST        63

struct blowfish {
    uint32_t p[18];
    uint32_t s[4][256];
};

/* Initialize a cipher context with the given key.
 *
 * The maximum key length is 72 bytes. Generally the key length should
 * not exceed 56 bytes since the last 16 bytes do not affect every bit
 * of each subkey.
 */
void blowfish_init(struct blowfish *, const void *key, int len);

/* Encrypt a pair of 32-bit integers using the given context.
 */
void blowfish_encrypt(struct blowfish *, uint32_t *, uint32_t *);

/* Decrypt a pair of 32-bit integers using the given context.
 */
void blowfish_decrypt(struct blowfish *, uint32_t *, uint32_t *);

/* Compute the bcrypt digest for a given password.
 *
 * All inputs and outputs are raw bytes, not base-64 encoded.
 *
 * The digest must have space for 24 bytes (BLOWFISH_DIGEST_LENGTH).
 *
 * The maximum password length is 72 bytes. Note: As a convention,
 * OpenBSD's bcrypt() includes the null terminator byte in the key.
 *
 * The salt must be 16 bytes (BLOWFISH_SALT_LENGTH).
 *
 * The maximum cost is 63.
 */
void blowfish_bcrypt(
    void *digest,
    const void *pwd,
    int len,
    const void *salt,
    int cost
);

#endif

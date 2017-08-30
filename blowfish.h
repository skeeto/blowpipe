/* C99 Blowfish implementation
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

#define BLOWFISH_SALT_LENGTH   16
#define BLOWFISH_DIGEST_LENGTH 24

struct blowfish {
    uint32_t p[18];
    uint32_t s[4][256];
};

/* Initialize a cipher context with the given key.
 *
 * The key length must be between 1 and 72 bytes.
 */
void blowfish_init(struct blowfish *, const void *key, int len);

/* Encrypt a buffer using the given context.
 *
 * The buffer length must be a multiple of the block size (8). The
 * source and destination can be the same buffer.
 */
void blowfish_encrypt(struct blowfish *, void *dst, const void *src, size_t);

/* Decrypt a buffer using the given context.
 *
 * The buffer length must be a multiple of the block size (8). The
 * source and destination can be the same buffer.
 */
void blowfish_decrypt(struct blowfish *, void *dst, const void *src, size_t);

/* Compute the bcrypt digest for a given password.
 *
 * The digest is 24 raw bytes (not base-64 encoded).
 *
 * The password length must be between 1 and 72 bytes. Note: As a
 * convention, OpenBSD's bcrypt() includes the null terminator byte in
 * the key.
 *
 * The salt must be 16 bytes.
 */
void blowfish_bcrypt(
    void *digest,
    const void *pwd,
    int pwdlen,
    const void *salt,
    int cost
);

#endif

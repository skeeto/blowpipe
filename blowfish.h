/* C99 big endian Blowfish implementation
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

struct blowfish {
    uint32_t p[18];
    uint32_t s[4][256];
};

/* Initialize a cipher context with the given key.
 *
 * The key length must be between 1 and 72 bytes.
 */
void blowfish_init(struct blowfish *, const void *, int);

/* Encrypt a buffer using the given context.
 *
 * The buffer length must be a multiple of the block size (8). The source and
 * destination can be the same buffer.
 */
void blowfish_encrypt(struct blowfish *, void *dst, const void *src, size_t);

/* Decrypt a buffer using the given context.
 *
 * The buffer length must be a multiple of the block size (8). The source and
 * destination can be the same buffer.
 */
void blowfish_decrypt(struct blowfish *, void *dst, const void *src, size_t);

#endif

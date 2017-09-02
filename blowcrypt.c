/* Blowfish command line encryption tool
 *
 * This is a toy symmetric file encryption tool that demonstrates the
 * associated Blowfish library. Every cryptographic primitive is built
 * entirely from the Blowfish cipher:
 *
 * - The key is derived from a passphrase using bcrypt.
 * - The stream is encrypted with Blowfish in CTR mode.
 * - The message authentication code is CBC-MAC (Blowfish in CBC mode).
 *
 * This tool doesn't open files for reading and writing. Instead it's
 * entirely stream oriented, processing standard input to standard
 * output.
 *
 *   $ gzip < data.txt | blowcrypt -E > data.txt.gz.enc
 *   $ blowcrypt -D < data.txt.gz.enc | gunzip > data.txt
 *
 * Or with a key file:
 *
 *   $ blowcrypt -E -kkeyfile <data.zip >data.zip.enc
 *   $ blowcrypt -D -kkeyfile >data.zip <data.zip.enc
 *
 * On decryption, the tool doesn't produce output until it has been
 * authenticated. However, the overall output could still be truncated
 * should something go wrong in the middle of a long stream. If the
 * stream has been truncated, an error message will be produced and the
 * exit status will reflect the error.
 *
 * ## Known issues
 *
 * Since Blowfish is a 64-bit block cipher, it's only safe to encrypt up
 * to a few GBs at a time before birthday attacks become an issue.
 * However, because of the IV, it's perfectly safe to reuse a password
 * or key file to encrypt an arbitrary amount of data across separate
 * limited runs. Otherwise, Blowfish is still a solid cipher. Despite
 * being a toy, this tool is far more secure than the other "bcrypt"
 * file encryption tool.
 *
 * ## Options
 *
 *   -D       decrypt standard input to standard output
 *   -E       encrypt standard input to standard output
 *   -c cost  set the bcrypt cost (encryption only)
 *   -k file  read key material from given file
 *
 * ## File format
 *
 * The overall file format:
 *
 * - 16-byte random initialization vector (IV)
 * - 1-byte bcrypt cost: last IV byte + cost, modulo 256
 * - one or more chunks
 *
 * The format is stream-oriented and data is processed in separate
 * chunks up to 64kB in size, each with its own MAC. A special
 * zero-length chunk is used to mark the end of the stream, and any data
 * following this chunk is silently ignored.
 *
 * The format for a chunk:
 *
 * - 8 byte MAC (continued from previous chunk)
 * - 2 byte big endian message length, encrypted [msglen]
 * - (round_up_to_block(msglen) - 2) bytes of encrypted data
 *
 * The last block's plaintext is zero padded. The last chunk will have a
 * "msglen" of 2, making it an empty chunk. Since this chunk is
 * authenticated, an attacker could not prematurely terminate the stream
 * without being detected.
 */

#define _POSIX_SOURCE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <termios.h>

#include "blowfish.h"

#define IV_LENGTH       16
#define CHUNK_SIZE      (1UL << 16)
#define PASSPHRASE_COST 14
#define KEYFILE_COST    0

#define DIE(s) \
    do { \
        fprintf(stderr, "blowcrypt: fatal: %s\n", s); \
        exit(EXIT_FAILURE); \
    } while (0)

#define DIE_ERRNO(s) \
    do { \
        fprintf(stderr, "blowcrypt: fatal: %s: %s\n", s, strerror(errno)); \
        exit(EXIT_FAILURE); \
    } while (0)

static ssize_t
full_read(int fd, void *buf, size_t len)
{
    size_t z = 0;
    while (z < len) {
        ssize_t r = read(fd, (char *)buf + z, len - z);
        if (r == -1)
            return -1;
        if (r == 0)
            break;
        z += r;
    }
    return z;
}

static void
gen_iv(void *iv)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
        DIE_ERRNO("/dev/urandom");
    ssize_t z = full_read(fd, iv, IV_LENGTH);
    if (z < 0)
        DIE_ERRNO("/dev/urandom");
    if (z != IV_LENGTH)
        DIE("/dev/urandom IV generation failed");
    close(fd);
}

static void
read_iv(int fd, void *iv)
{
    ssize_t z = full_read(fd, iv, IV_LENGTH + 1);
    if (z < 0)
        DIE_ERRNO("reading ciphertext");
    if (z < IV_LENGTH)
        DIE("premature end of ciphertext");
}

static int
passphrase_prompt(const char *prompt, char *buf)
{
    int tty = open("/dev/tty", O_RDWR);
    if (tty == -1)
        DIE_ERRNO("/dev/tty");

    if (write(tty, prompt, strlen(prompt)) != strlen(prompt))
        DIE_ERRNO("/dev/tty");

    struct termios old, new;
    if (tcgetattr(tty, &old) == -1)
        DIE_ERRNO("tcgetattr()");
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(tty, TCSANOW, &new) == -1)
        DIE_ERRNO("tcsetattr()");

    ssize_t z = read(tty, buf, BLOWFISH_MAX_KEY_LENGTH + 1);
    tcsetattr(tty, TCSANOW, &old);
    write(tty, "\n", 1);

    int result = 0;
    if (z < 0)
        DIE_ERRNO("/dev/tty");
    if (z == 0 || buf[0] == '\n')
        fputs("passphrase too short (must 1 to 72 bytes)\n", stderr);
    else if (z > BLOWFISH_MAX_KEY_LENGTH && buf[z] != '\n')
        fputs("passphrase too long (must 1 to 72 bytes)\n", stderr);
    else {
        buf[z - 1] = 0;
        result = 1;
    }
    return result;
}

static void
passphrase_kdf(void *key, const void *iv, int cost, int verify)
{
    char buf[2][BLOWFISH_MAX_KEY_LENGTH + 1];
    while (!passphrase_prompt("Passphrase: ", buf[0]))
        ;
    if (verify) {
        while (!passphrase_prompt("Passphrase (repeat): ", buf[1]))
            ;
        if (strcmp(buf[0], buf[1]) != 0)
            DIE("passphrases do not match");
    }
    blowfish_bcrypt(key, buf, strlen(buf[0]) + 1, iv, cost);
}

static void
key_read(int fd, void *key, const void *iv, int cost)
{
    /* Read one over the maximum key length. The extra character will
     * detect an overly-long key.
     */
    char buf[BLOWFISH_MAX_KEY_LENGTH + 1];
    ssize_t z = full_read(fd, buf, BLOWFISH_MAX_KEY_LENGTH + 1);
    if (z < 0)
        DIE_ERRNO("reading key");
    if (z < BLOWFISH_MIN_KEY_LENGTH)
        DIE("key is too short");
    if (z > BLOWFISH_MAX_KEY_LENGTH)
        DIE("key is too long");
    blowfish_bcrypt(key, buf, z, iv, cost);
}

static void
spill(void *buf, uint64_t c)
{
    uint8_t *p = buf;
    p[0] = (uint8_t)(c >>  0);
    p[1] = (uint8_t)(c >>  8);
    p[2] = (uint8_t)(c >> 16);
    p[3] = (uint8_t)(c >> 24);
    p[4] = (uint8_t)(c >> 32);
    p[5] = (uint8_t)(c >> 40);
    p[6] = (uint8_t)(c >> 48);
    p[7] = (uint8_t)(c >> 56);
}

static uint64_t
fill(void *buf, size_t len, uint64_t ctr, struct blowfish *ctx)
{
    assert(len % 8 == 0);

    uint8_t *p = buf;
    for (size_t n = 0; n < len; n += 8)
        spill(p + n, ctr++);
    blowfish_encrypt(ctx, buf, buf, len);
    return ctr;
}

static void
encrypt(int in, int out, struct blowfish *crypt, struct blowfish *mac)
{
    uint64_t ctr = 0;
    static uint8_t chunk[CHUNK_SIZE];

    memset(chunk, 0, BLOWFISH_BLOCK_LENGTH);
    for (;;) {
        int headerlen = BLOWFISH_BLOCK_LENGTH + 2;
        ssize_t z = read(in, chunk + headerlen, CHUNK_SIZE - headerlen);
        if (z < 0)
            DIE_ERRNO("reading plaintext");

        /* Zero-pad last block */
        size_t blocklen = BLOWFISH_BLOCK_LENGTH;
        size_t msglen = z + 2;
        size_t nblocks = (msglen + blocklen - 1) / blocklen;
        size_t padding = nblocks * blocklen - msglen;
        memset(chunk + BLOWFISH_BLOCK_LENGTH + msglen + z, 0, padding);

        /* Write chunk length to chunk header */
        chunk[BLOWFISH_BLOCK_LENGTH + 0] = msglen >> 8;
        chunk[BLOWFISH_BLOCK_LENGTH + 1] = msglen >> 0;

        /* Encrypt the buffer */
        static uint8_t pad[CHUNK_SIZE];
        ctr = fill(pad, nblocks * BLOWFISH_BLOCK_LENGTH, ctr, crypt);
        for (size_t i = 0; i < nblocks * BLOWFISH_BLOCK_LENGTH; i++)
            chunk[i + BLOWFISH_BLOCK_LENGTH] ^= pad[i];

        /* Compute MAC */
        for (size_t i = 0; i < nblocks; i++) {
            for (int j = 0; j < BLOWFISH_BLOCK_LENGTH; j++)
                chunk[j] ^= chunk[(i + 1) * BLOWFISH_BLOCK_LENGTH + j];
            blowfish_encrypt(mac, chunk, chunk, BLOWFISH_BLOCK_LENGTH);
        }

        /* Write encrypted chunk */
        size_t len = (nblocks + 1) * BLOWFISH_BLOCK_LENGTH;
        ssize_t w = write(out, chunk, len);
        if (w < 0)
            DIE_ERRNO("reading ciphertext");
        if (w != len)
            DIE("failed to write ciphertext");

        if (z == 0)
            break; // EOF
    }

}

static uint64_t
mac_check(uint8_t *mac0, uint8_t *mac1)
{
    /* Use integers to (hopefully) get constant-time comparison */
    uint64_t i0, i1;
    memcpy(&i0, mac0, BLOWFISH_BLOCK_LENGTH);
    memcpy(&i1, mac1, BLOWFISH_BLOCK_LENGTH);
    return i0 ^ i1;
}

static void
decrypt(int in, int out, struct blowfish *crypt, struct blowfish *mac)
{
    size_t len = 0;
    uint64_t ctr = 0;
    static uint8_t pad[CHUNK_SIZE];
    static uint8_t chunk[CHUNK_SIZE];
    uint8_t cbcmac[BLOWFISH_BLOCK_LENGTH] = {0};

    for (;;) {
        int headerlen = BLOWFISH_BLOCK_LENGTH + 2;

        /* Read in at least the header */
        while (len < headerlen) {
            ssize_t z = read(in, chunk + len, CHUNK_SIZE - len);
            if (z < 0)
                DIE_ERRNO("reading ciphertext");
            if (z == 0)
                DIE("premature end of ciphertext");
            len += z;
        }

        /* Decrypt the chunk length */
        size_t msglen;
        ctr = fill(pad, BLOWFISH_BLOCK_LENGTH, ctr, crypt);
        msglen  = (uint16_t)(chunk[BLOWFISH_BLOCK_LENGTH + 0] ^ pad[0]) << 8;
        msglen |= (uint16_t)(chunk[BLOWFISH_BLOCK_LENGTH + 1] ^ pad[1]) << 0;
        if (msglen > CHUNK_SIZE - BLOWFISH_BLOCK_LENGTH)
            DIE("ciphertext is corrupt");

        /* Read remainder of chunk */
        size_t blocklen = BLOWFISH_BLOCK_LENGTH;
        size_t nblocks = (msglen + blocklen - 1) / blocklen;
        ssize_t remainder = (nblocks * blocklen) - len - blocklen;
        if (remainder > 0) {
            ssize_t z = full_read(in, chunk + len, remainder);
            if (z < 0)
                DIE_ERRNO("reading ciphertext");
            if (z != remainder)
                DIE("premature end of ciphertext");
        }

        /* Check the MAC */
        for (size_t i = 0; i < nblocks; i++) {
            for (int j = 0; j < BLOWFISH_BLOCK_LENGTH; j++)
                cbcmac[j] ^= chunk[(i + 1) * BLOWFISH_BLOCK_LENGTH + j];
            blowfish_encrypt(mac, cbcmac, cbcmac, BLOWFISH_BLOCK_LENGTH);
        }
        if (mac_check(cbcmac, chunk))
            DIE("ciphertext is currupt");

        /* Decrypt validated ciphertext */
        ctr = fill(pad + blocklen, (nblocks - 1) * blocklen, ctr, crypt);
        for (size_t i = 0; i < nblocks * BLOWFISH_BLOCK_LENGTH; i++)
            chunk[BLOWFISH_BLOCK_LENGTH + i] ^= pad[i];

        /* Write out decrypted ciphertext */
        ssize_t w = write(out, chunk + headerlen, msglen - 2);
        if (w < 0)
            DIE_ERRNO("writing plaintext");
        if (w != msglen - 2)
            DIE("failed to write plaintext");

        /* Move unprocessed bytes to beginning */
        size_t discard = (nblocks + 1) * BLOWFISH_BLOCK_LENGTH;
        memmove(chunk, chunk + discard, len - discard);
        len -= discard;

        if (msglen == 2)
            break;
    }
}

static void
usage(FILE *o)
{
    fprintf(o, "usage: example [-D|-E] [-c cost] [-k file]\n");
}

int
main(int argc, char **argv)
{
    /* Options */
    const char *keyfile = 0;
    int cost = -1;
    enum {MODE_ENCRYPT = 1, MODE_DECRYPT} mode = 0;

    int option;
    while ((option = getopt(argc, argv, "DEc:hk:")) != -1) {
        switch (option) {
            case 'E':
                mode = MODE_ENCRYPT;
                break;
            case 'D':
                mode = MODE_DECRYPT;
                break;
            case 'c':
                cost = atoi(optarg);
                if (cost < BLOWFISH_MIN_COST || cost > BLOWFISH_MAX_COST)
                    DIE("invalid cost (must be 1 to 63)");
                break;
            case 'h':
                usage(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'k':
                keyfile = optarg;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    /* Check for invalid option combinations */
    if (mode == MODE_DECRYPT && cost != -1)
        DIE("cost option (-c) is only for encryption (-E)");

    char iv[IV_LENGTH + 1];
    struct blowfish crypt[1];
    struct blowfish mac[1];

    /* Get the IV before asking for a password, in case it fails */
    switch (mode) {
        case MODE_ENCRYPT:
            gen_iv(iv);
            break;
        case MODE_DECRYPT:
            read_iv(STDIN_FILENO, iv);
            cost = iv[IV_LENGTH] + 256;
            cost = (cost - iv[IV_LENGTH - 1]) % 256;
            if (cost > BLOWFISH_MAX_COST)
                DIE("ciphertext is damaged");
            break;
        default:
            fputs("must select encrypt (-E) or decrypt (-D)\n", stderr);
            usage(stderr);
            exit(EXIT_FAILURE);
    }

    /* Derive the key */
    char key[BLOWFISH_DIGEST_LENGTH];
    if (!keyfile) {
        int verify = mode == MODE_ENCRYPT;
        if (cost == -1)
            cost = PASSPHRASE_COST;
        passphrase_kdf(key, iv, cost, verify);
    } else {
        int fd = open(keyfile, O_RDONLY);
        if (fd == -1)
            DIE_ERRNO(keyfile);
        if (cost == -1)
            cost = KEYFILE_COST;
        key_read(fd, key, iv, cost);
        close(fd);
    }
    iv[IV_LENGTH] = iv[IV_LENGTH - 1] + cost;
    blowfish_init(crypt, key, BLOWFISH_DIGEST_LENGTH);

    /* Initialize the MAC by deriving another key */
    uint8_t zero[BLOWFISH_SALT_LENGTH] = {0};
    char mackey[BLOWFISH_DIGEST_LENGTH];
    blowfish_bcrypt(mackey, key, BLOWFISH_DIGEST_LENGTH, zero, 0);
    blowfish_init(mac, mackey, BLOWFISH_DIGEST_LENGTH);

    ssize_t z;
    switch (mode) {
        case MODE_ENCRYPT:
            z = write(STDOUT_FILENO, iv, IV_LENGTH + 1);
            if (z < 0)
                DIE_ERRNO("writing ciphertext");
            if (z < IV_LENGTH + 1)
                DIE("failed to write ciphertext");
            encrypt(STDIN_FILENO, STDOUT_FILENO, crypt, mac);
            break;
        case MODE_DECRYPT:
            decrypt(STDIN_FILENO, STDOUT_FILENO, crypt, mac);
            break;
    }
}

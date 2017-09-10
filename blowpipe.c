/* Blowpipe --- authenticated Blowfish-encrypted pipe */
#define _POSIX_SOURCE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "w32-compat/unistd.h"
#include "w32-compat/getopt.h"
#else
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <termios.h>
#endif

#include "blowfish.h"

#define IV_LENGTH          16
#define CHUNK_SIZE         (1UL << 16)
#define CHUNK_SIZE_SIZE    2
#define PASSPHRASE_COST    15
#define KEYFILE_COST       0
#define MAXIMUM_INPUT_COST 16

#define DIE(...) \
    do { \
        fprintf(stderr, "blowcrypt: fatal: " __VA_ARGS__); \
        fputc('\n', stderr); \
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
    if (z == -1)
        DIE_ERRNO("/dev/urandom");
    if (z != IV_LENGTH)
        DIE("/dev/urandom IV generation failed");
    close(fd);
}

static void
read_iv(int fd, void *iv)
{
    ssize_t z = full_read(fd, iv, IV_LENGTH + 1);
    if (z == -1)
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

    if (write(tty, prompt, strlen(prompt)) != (ssize_t)strlen(prompt))
        DIE_ERRNO("/dev/tty");

    struct termios old, new;
    if (tcgetattr(tty, &old) == -1)
        DIE_ERRNO("tcgetattr()");
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(tty, TCSANOW, &new) == -1)
        DIE_ERRNO("tcsetattr()");

    ssize_t z = read(tty, buf, BLOWFISH_MAX_KEY_LENGTH + 1);
    (void)tcsetattr(tty, TCSANOW, &old);  // don't care if this fails
    (void)write(tty, "\n", 1);            // don't care if this fails

    int result = 0;
    if (z == -1)
        DIE_ERRNO("/dev/tty");
    if (z == 0 || buf[0] == '\n' || buf[0] == '\r')
        fputs("passphrase too short (must 1 to 72 bytes)\n", stderr);
    else if (z > BLOWFISH_MAX_KEY_LENGTH && buf[z] != '\n')
        fputs("passphrase too long (must 1 to 72 bytes)\n", stderr);
    else {
        if (z >= 2 && buf[z - 2] == '\r')
            buf[z - 2] = 0;
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
    if (z == -1)
        DIE_ERRNO("reading key");
    if (z < BLOWFISH_MIN_KEY_LENGTH)
        DIE("key is too short, must be between 1 and 72 bytes");
    if (z > BLOWFISH_MAX_KEY_LENGTH)
        DIE("key is too long, must be between 1 and 72 bytes");
    blowfish_bcrypt(key, buf, z, iv, cost);
}

static void
encode_u32be(void *buf, uint32_t c)
{
    uint8_t *p = buf;
    p[0] = (uint8_t)(c >> 24);
    p[1] = (uint8_t)(c >> 16);
    p[2] = (uint8_t)(c >>  8);
    p[3] = (uint8_t)(c >>  0);
}

static uint32_t
decode_u32be(const void *buf)
{
    const uint8_t *p = buf;
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3] <<  0);
}

#define FLAG_WAIT (1u << 0)

static void
encrypt(struct blowfish *crypt, struct blowfish *mac, unsigned flags)
{
    int eof = 0;
    uint64_t ctr = 0;
    uint32_t macl = 0;
    uint32_t macr = 0;
    static uint8_t chunk[CHUNK_SIZE];

    for (;;) {
        ssize_t z;
        int headerlen = BLOWFISH_BLOCK_LENGTH + CHUNK_SIZE_SIZE;
        if (flags & FLAG_WAIT) {
            /* Read as much input as possible, but don't ever read()
             * again after getting 0 bytes on a read().
             */
            size_t avail = CHUNK_SIZE - headerlen;
            z = 0;
            while (!eof && avail) {
                ssize_t r = read(STDIN_FILENO, chunk + headerlen + z, avail);
                if (r == -1)
                    break;
                if (r == 0)
                    eof = 1;
                z += r;
                avail -= r;
            }
        } else {
            /* Read just the available data */
            size_t avail = CHUNK_SIZE - headerlen;
            z = read(STDIN_FILENO, chunk + headerlen, avail);
        }
        if (z == -1)
            DIE_ERRNO("reading plaintext");

        /* Zero-pad last block */
        size_t blocklen = BLOWFISH_BLOCK_LENGTH;
        size_t msglen = z + CHUNK_SIZE_SIZE;
        size_t nblocks = (msglen + blocklen - 1) / blocklen;
        size_t padding = nblocks * blocklen - msglen;
        memset(chunk + BLOWFISH_BLOCK_LENGTH + msglen, 0, padding);

        /* Write chunk length to chunk header */
        for (int i = 0; i < CHUNK_SIZE_SIZE; i++) {
            int shift = (CHUNK_SIZE_SIZE - 1 - i) * 8;
            chunk[BLOWFISH_BLOCK_LENGTH + i] = msglen >> shift;
        }

        /* Encrypt the buffer */
        for (size_t i = 0; i < nblocks; i++) {
            /* Compute CTR mode pad */
            uint32_t xl = ctr >> 32;
            uint32_t xr = ctr++;
            blowfish_encrypt(crypt, &xl, &xr);

            /* XOR plaintext with the pad */
            size_t off = (i + 1) * BLOWFISH_BLOCK_LENGTH;
            xl ^= decode_u32be(chunk + off + 0);
            xr ^= decode_u32be(chunk + off + 4);

            /* Compute the MAC */
            macl ^= xl;
            macr ^= xr;
            blowfish_encrypt(mac, &macl, &macr);

            /* Put ciphertext back into the buffer */
            encode_u32be(chunk + off + 0, xl);
            encode_u32be(chunk + off + 4, xr);
        }
        encode_u32be(chunk + 0, macl);
        encode_u32be(chunk + 4, macr);

        /* Write encrypted chunk */
        ssize_t len = msglen + BLOWFISH_BLOCK_LENGTH;
        ssize_t w = write(STDOUT_FILENO, chunk, len);
        if (w == -1)
            DIE_ERRNO("reading ciphertext");
        if (w != len)
            DIE("failed to write ciphertext");

        if (z == 0)
            break; // EOF
    }

}

static void
decrypt(struct blowfish *crypt, struct blowfish *mac)
{
    size_t len = 0;
    uint64_t ctr = 0;
    uint32_t macl = 0;
    uint32_t macr = 0;
    static uint8_t chunk[CHUNK_SIZE];

    for (;;) {
        /* Read in at least the header */
        size_t headerlen = BLOWFISH_BLOCK_LENGTH + CHUNK_SIZE_SIZE;
        while (len < headerlen) {
            ssize_t z = read(STDIN_FILENO, chunk + len, CHUNK_SIZE - len);
            if (z == -1)
                DIE_ERRNO("reading ciphertext");
            if (z == 0)
                DIE("premature end of ciphertext");
            len += z;
        }

        /* Compute the first 8 bytes of the pad */
        uint8_t pad[BLOWFISH_BLOCK_LENGTH];
        uint32_t padl = ctr >> 32;
        uint32_t padr = ctr;  // don't increment counter yet
        blowfish_encrypt(crypt, &padl, &padr);
        encode_u32be(pad + 0, padl);
        encode_u32be(pad + 4, padr);

        /* Decrypt the chunk length */
        size_t msglen = 0;
        for (int i = 0; i < CHUNK_SIZE_SIZE; i++) {
            msglen <<= 8;
            msglen |= chunk[BLOWFISH_BLOCK_LENGTH + i] ^ pad[i];
        }
        size_t msglen_min = CHUNK_SIZE_SIZE;
        size_t msglen_max = CHUNK_SIZE - BLOWFISH_BLOCK_LENGTH;
        if (msglen < msglen_min || msglen > msglen_max)
            DIE("ciphertext is damaged");

        /* Read remainder of chunk */
        size_t blocklen = BLOWFISH_BLOCK_LENGTH;
        size_t nblocks = (msglen + blocklen - 1) / blocklen;
        ssize_t remainder = msglen - len + blocklen;
        if (remainder > 0) {
            ssize_t z = full_read(STDIN_FILENO, chunk + len, remainder);
            if (z == -1)
                DIE_ERRNO("reading ciphertext");
            if (z != remainder)
                DIE("premature end of ciphertext");
            len += z;
        }

        /* Decrypt the buffer */
        for (size_t i = 0; i < nblocks; i++) {
            uint32_t pl = ctr >> 32;
            uint32_t pr = ctr++;
            blowfish_encrypt(crypt, &pl, &pr);

            /* Extract ciphertext */
            uint32_t cl, cr;
            size_t off = (i + 1) * BLOWFISH_BLOCK_LENGTH;
            if ((i + 1) * BLOWFISH_BLOCK_LENGTH > msglen) {
                /* Handle the final partial block in a temporary buffer
                 * in order to pad it. The chunk buffer might have bytes
                 * belonging to the next chunk immediately after this
                 * partial block, so that space isn't available.
                 */
                uint8_t tmp[BLOWFISH_BLOCK_LENGTH];
                int padding = (i + 1) * BLOWFISH_BLOCK_LENGTH - msglen;
                encode_u32be(tmp + 0, pl);
                encode_u32be(tmp + 4, pr);
                memcpy(tmp, chunk + off, 8 - padding);
                cl = decode_u32be(tmp + 0);
                cr = decode_u32be(tmp + 4);
                encode_u32be(tmp + 0, pl ^ cl);
                encode_u32be(tmp + 4, pr ^ cr);
                memcpy(chunk + off, tmp, 8 - padding);
            } else {
                cl = decode_u32be(chunk + off + 0);
                cr = decode_u32be(chunk + off + 4);
                encode_u32be(chunk + off + 0, pl ^ cl);
                encode_u32be(chunk + off + 4, pr ^ cr);
            }

            /* Compute MAC */
            macl ^= cl;
            macr ^= cr;
            blowfish_encrypt(mac, &macl, &macr);
        }

        /* Check the MAC */
        uint32_t cl = decode_u32be(chunk + 0);
        uint32_t cr = decode_u32be(chunk + 4);
        if (macl != cl || macr != cr)
            DIE("ciphertext is damaged");

        /* Quit after the empty chunk has been authenticated */
        if (msglen == CHUNK_SIZE_SIZE)
            break;

        /* Write out decrypted ciphertext */
        size_t outlen = msglen - CHUNK_SIZE_SIZE;
        ssize_t w = write(STDOUT_FILENO, chunk + headerlen, outlen);
        if (w == -1)
            DIE_ERRNO("writing plaintext");
        if ((size_t)w != outlen)
            DIE("failed to write plaintext");

        /* Move unprocessed bytes to beginning */
        size_t discard = msglen + BLOWFISH_BLOCK_LENGTH;
        memmove(chunk, chunk + discard, len - discard);
        len -= discard;
    }
}

static void
usage(FILE *o)
{
    fprintf(o, "usage: blowpipe [-D|-E] [-c cost] [-k file] [-w]\n");
}

int
main(int argc, char **argv)
{
    /* Options */
    const char *keyfile = 0;
    int cost = -1;
    unsigned eflags = 0;
    enum {MODE_ENCRYPT = 1, MODE_DECRYPT} mode = 0;

    int option;
    while ((option = getopt(argc, argv, "DEc:hk:w")) != -1) {
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
            case 'w':
                eflags |= FLAG_WAIT;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    /* Check for invalid option combinations */
    if (mode == MODE_DECRYPT && (eflags & FLAG_WAIT))
        DIE("wait option (-w) is only for encryption (-E)");

    char iv[IV_LENGTH + 1];
    struct blowfish crypt[1];
    struct blowfish mac[1];

    /* Get the IV before asking for a password, in case it fails */
    switch (mode) {
        case MODE_ENCRYPT: {
            gen_iv(iv);
        } break;
        case MODE_DECRYPT: {
            read_iv(STDIN_FILENO, iv);
            int in_cost = iv[IV_LENGTH] + 256;
            in_cost = (in_cost - iv[IV_LENGTH - 1]) % 256;
            if (in_cost > BLOWFISH_MAX_COST)
                DIE("ciphertext is damaged");
            if (cost == -1)
                cost = MAXIMUM_INPUT_COST;
            if (in_cost > cost)
                DIE("bcrypt cost exceeds maximum (%d > %d), use -c to adjust",
                    in_cost, cost);
            cost = in_cost;
        } break;
        default: {
            fputs("blowpipe: ", stderr);
            fputs("must select encrypt (-E) or decrypt (-D)\n", stderr);
            usage(stderr);
            exit(EXIT_FAILURE);
        }
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
            if (z == -1)
                DIE_ERRNO("writing ciphertext");
            if (z < IV_LENGTH + 1)
                DIE("failed to write ciphertext");
            encrypt(crypt, mac, eflags);
            break;
        case MODE_DECRYPT:
            decrypt(crypt, mac);
            break;
    }
}

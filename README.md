# C99 Public Domain Blowfish Cipher

This is a public domain implementation of the [Blowfish cipher][bfsh].
It is a strictly conforming C99 program with no platform-specific code.

~~~c
void blowfish_init(struct blowfish *, const void *, int);
void blowfish_encrypt(struct blowfish *, void *dst, const void *src, size_t);
void blowfish_decrypt(struct blowfish *, void *dst, const void *src, size_t);
void blowfish_bcrypt(void *digest, const void *pwd, int len, const void *salt, int cost);
~~~

See `blowfish.h` for complete API documentation.

## File encryption tool

A *toy* symmetric file encryption tool called `blowcrypt` demonstrates
the associated Blowfish library. Every cryptographic primitive is built
entirely from the Blowfish cipher:

* The key is derived from a passphrase using bcrypt.
* The stream is encrypted with Blowfish in CTR mode.
* Message authentication code is CBC-MAC (Blowfish in CBC mode).

This tool doesn't open any files for reading and writing. Instead it
processes standard input to standard output.

    $ blowcrypt -E < data.gz > data.gz.enc
    $ blowcrypt -D < data.gz.enc | gunzip > data.txt

Or with a key file:

    $ blowcrypt -E -k keyfile < data.zip > data.zip.enc
    $ blowcrypt -D -k keyfile > data.zip < data.zip.enc

The CBC-MAC usage is a little dubious, especially considering these are
variable-length messages. However, it's seeded with a unique, one-time
key, separate from the CTR mode key, so hopefully there aren't any real
issues.

Since Blowfish is a 64-bit block cipher, it's really only safe to
encrypt up to a few GBs at a time due to birthday attacks. However,
because of the IV, it's perfectly safe to reuse the same password or key
file to encrypt large amounts of data in separate runs. Otherwise,
Blowfish is still a solid cipher. Despite being just a toy, this tool is
far more secure than the *other* "bcrypt" file encryption tool.


[bfsh]: https://www.schneier.com/academic/blowfish/

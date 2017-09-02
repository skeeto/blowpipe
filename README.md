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

This tool doesn't open files for reading and writing. Instead it's
entirely stream oriented, processing standard input to standard output.

    $ blowcrypt -E < data.gz > data.gz.enc
    $ blowcrypt -D < data.gz.enc | gunzip > data.txt

Or with a key file:

    $ blowcrypt -E -k keyfile < data.zip > data.zip.enc
    $ blowcrypt -D -k keyfile > data.zip < data.zip.enc

On decryption, the tool doesn't produce output until it has been
authenticated. However, the overall output could still be truncated
should something go wrong in the middle of a long stream. If the stream
has been truncated, an error message will be produced and the exit
status will reflect the error.

Since Blowfish is a 64-bit block cipher, it's only safe to encrypt up to
a few GBs at a time before birthday attacks become an issue. However,
because of the IV, it's perfectly safe to reuse a password or key file
to encrypt an arbitrary amount of data across separate limited runs.
Otherwise, Blowfish is still a solid cipher. Despite being a toy, this
tool is far more secure than the other "bcrypt" file encryption tool.


[bfsh]: https://www.schneier.com/academic/blowfish/

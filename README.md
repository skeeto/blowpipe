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

## Blowpipe: authenticated Blowfish encrypted pipe

A *toy* symmetric, authenticated pipe encryption tool called `blowpipe`
demonstrates the associated Blowfish library. Every cryptographic
primitive is built entirely from the Blowfish cipher:

* The key is derived from a passphrase using bcrypt.
* The stream is encrypted with Blowfish in CTR mode.
* The message authentication code is CBC-MAC (Blowfish in CBC mode).

This tool doesn't open files for reading and writing. Instead it's
entirely stream oriented, processing standard input to standard output.

    $ blowpipe -E < data.gz > data.gz.enc
    $ blowpipe -D < data.gz.enc | gunzip > data.txt

Or with a key file:

    $ blowpipe -E -k keyfile < data.zip > data.zip.enc
    $ blowpipe -D -k keyfile > data.zip < data.zip.enc

On decryption, the tool *only* produces authenticated output. However,
the overall output could still be truncated should something go wrong in
the middle of a long stream. If the stream has been truncated, an error
message will be produced and the exit status will reflect the error.

Since Blowfish is a 64-bit block cipher, it's only safe to encrypt up to
a few GBs at a time before birthday attacks become an issue. However,
because of the IV, it's perfectly safe to reuse a password or key file
to encrypt an arbitrary amount of data across separate runs. Otherwise,
Blowfish is still a solid cipher. Despite being a toy, this tool is far
more secure than the other "bcrypt" file encryption tool.

## Options

    -D       decrypt standard input to standard output
    -E       encrypt standard input to standard output
    -c cost  set the bcrypt cost (encryption only)
    -k file  read key material from given file
    -w       wait for full chunks and don't flush early

## File format

The overall file format:

* 16-byte random initialization vector (IV)
* 1-byte bcrypt cost: last IV byte + cost, modulo 256
* one or more chunks

The format is stream-oriented and data is processed in separate chunks
up to 64kB in size, each with its own MAC. A special zero-length chunk
marks the end of the stream, and any data following this chunk is
ignored.

The format chunks:

* 8 byte MAC for this chunk (continued from previous chunk)
* 2 byte big endian message length, encrypted and authenticated (`msglen`)
* `round_up_to_block(msglen) - 2` bytes of encrypted data

The last block's plaintext is zero padded. The last chunk will have a
`msglen` of 2, making it an empty chunk. Since this chunk is
authenticated, an attacker could not prematurely terminate the stream
without being detected.


[bfsh]: https://www.schneier.com/academic/blowfish/

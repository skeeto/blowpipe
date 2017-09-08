# Blowpipe: authenticated Blowfish-encrypted pipe

Blowpipe is a *toy* that creates an authenticated,
[Blowfish][bfsh]-encrypted pipe. Each cryptographic primitive it uses is
built entirely with the Blowfish cipher:

* The key is derived from a passphrase using [bcrypt][bcrypt].
* The stream is encrypted with Blowfish in [CTR mode][ctr].
* The message authentication code ([MAC][mac]) is
  [Blowfish-CBC-MAC][cbcmac] with fixed-length messages.

This tool is strictly stream oriented, processing standard input to
standard output. It could be used to encrypt a file (prompted for a
passphrase):

    $ blowpipe -E < data.gz > data.gz.enc
    $ blowpipe -D < data.gz.enc | gunzip > data.txt

Or to securely transfer a file over a network:

    # receiver
    $ nc -lp 2000 | blowpipe -D -k keyfile > data.zip || rm -f data.zip

    # sender
    $ blowpipe -E -k keyfile < data.zip | nc -N hostname 2000

On a modern desktop, Blowpipe has a throughput of about 75 MB/s.

![][img]

On decryption, the tool *only* produces authenticated output. However,
the overall output could still be truncated should something go wrong in
the middle of a long stream. If the stream has been truncated, an error
message will be produced and the exit status will reflect the error.

Since Blowfish is a 64-bit block cipher, it's only safe to encrypt up to
a few tens of GBs at a time before birthday attacks become an issue.
However, because of the initialization vector (IV), it's safe to reuse a
password or key file to encrypt an arbitrary amount of data across
separate runs. Other than the block size, Blowfish is still a solid
cipher.

Despite being a toy, Blowpipe is more secure than a few crypto tools
typically packaged by a Linux distribution, such as the ["bcrypt" file
encryption tool][bad] (unauthenticated, [ECB mode][ecb]) and
[aespipe][aespipe] (unauthenticated).

A proper alternative to Blowpipe is [aepipe][aepipe], which is built
upon a stronger, newer cipher (AES).

## Options

    -D       decrypt standard input to standard output
    -E       encrypt standard input to standard output
    -c cost  (encrypt) set the bcrypt cost
             (decrypt) set the maximum permitted bcrypt cost
    -k file  read key material from given file
    -w       wait for full chunks and don't flush early

## Wire format

The overall wire format:

* 16-byte random initialization vector (IV)
* 1-byte bcrypt cost: last IV byte + cost, modulo 256
* one or more chunks

The format is stream-oriented and data is processed in separate chunks
up to 64kB in size, each with its own MAC. A special zero-length chunk
marks the end of the stream, and any data following this chunk is
ignored.

The chunk format:

* 8 byte MAC for this chunk (continued from previous chunk)
* 2 byte big endian message length, encrypted and authenticated (`msglen`)
* `msglen - 2` bytes of encrypted data

The MAC is computed on the ciphertext. The last block in a chunk has its
plaintext zero padded before encryption and authentication, but these
bytes are not actually transmitted. The receiver must also zero-pad and
encrypt the padding before authenticating.

Since MACs are chained across chunks, it's not possible for an attacker
to reorder individual chunks. The last chunk in the stream will have a
`msglen` of 2, making it an empty chunk. Since this chunk and its
`msglen` are authenticated, an attacker cannot prematurely terminate the
stream without being detected.

# C99 Public Domain Blowfish Cipher

This repository includes a standalone Blowfish library (`blowfish.c`,
`blowfish.h`), ready to use in another project. It is a strictly
conforming C99 program with no platform-specific code.

~~~c
void blowfish_init(struct blowfish *, const void *, int);
void blowfish_encrypt(struct blowfish *, uint32_t *, uint32_t *);
void blowfish_decrypt(struct blowfish *, uint32_t *, uint32_t *);
void blowfish_bcrypt(void *digest, const void *pwd, int len, const void *salt, int cost);
~~~

See `blowfish.h` for complete API documentation.


[aepipe]: https://github.com/hashbrowncipher/keypipe
[aespipe]: http://loop-aes.sourceforge.net/aespipe.README
[bad]: http://bcrypt.sourceforge.net/
[bcrypt]: https://en.wikipedia.org/wiki/Bcrypt
[bfsh]: https://www.schneier.com/academic/blowfish/
[cbcmac]: https://en.wikipedia.org/wiki/CBC-MAC
[ctr]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR
[ecb]: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=700758
[img]: https://upload.wikimedia.org/wikipedia/commons/e/ec/Blowpipe2_(PSF).jpg
[mac]: https://en.wikipedia.org/wiki/Message_authentication_code

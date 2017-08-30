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

[bfsh]: https://www.schneier.com/academic/blowfish/

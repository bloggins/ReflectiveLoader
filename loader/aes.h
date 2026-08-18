#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/* AES-256-CBC, portable, no OS dependencies.
 * len must be a multiple of 16 (callers apply PKCS#7 padding). */

void aes256_cbc_encrypt(uint8_t *data, size_t len, const uint8_t key[32], const uint8_t iv[16]);
void aes256_cbc_decrypt(uint8_t *data, size_t len, const uint8_t key[32], const uint8_t iv[16]);

/* PKCS#7 helpers. pad: writes padded copy into dst (dst must hold srclen+16).
 * unpad: strips padding in place, returns 0 on success, -1 if padding invalid. */
void pkcs7_pad(const uint8_t *src, size_t srclen, uint8_t *dst, size_t *dstlen);
int  pkcs7_unpad(uint8_t *buf, size_t *len);

#endif

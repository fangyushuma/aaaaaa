#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <openssl\kdf.h>
#include <openssl\evp.h>

void hmac_sha1(unsigned char *key, int key_len, unsigned char *text, int text_len, unsigned char *digest)
{
  int i;
  unsigned char k_ipad[64];
  unsigned char k_opad[64];
  unsigned char tk[20];

  SHA_CTX ctx;

  if (key_len > 64)
  {
    SHA1(key, key_len, tk);

    SHA1(key, key_len, tk);
    key = tk;
    key_len = 20;
  }

  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  for (i = 0; i < 64; i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, k_ipad, 64);
  SHA1_Update(&ctx, text, text_len);
  SHA1_Final(digest, &ctx);

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, k_opad, 64);
  SHA1_Update(&ctx, digest, 20);
  SHA1_Final(digest, &ctx);
}

void hmac_md5(unsigned char *key, int key_len, unsigned char *text, int text_len, unsigned char *digest)
{
  int i;
  unsigned char k_ipad[64];
  unsigned char k_opad[64];
  unsigned char tk[16];

  MD5_CTX ctx;

  if (key_len > 64)
  {
    MD5(key, key_len, tk);

    key = tk;
    key_len = 16;
  }

  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  for (i = 0; i < 64; i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  MD5_Init(&ctx);
  MD5_Update(&ctx, k_ipad, 64);
  MD5_Update(&ctx, text, text_len);
  MD5_Final(digest, &ctx);

  MD5_Init(&ctx);
  MD5_Update(&ctx, k_opad, 64);
  MD5_Update(&ctx, digest, 16);
  MD5_Final(digest, &ctx);
}

int p_sha1(unsigned char *secret, int secret_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen)
{
  int loop = 0;
  int count = (outlen + 20 - 1) / 20;
  unsigned char a[20] = { 0 };
  unsigned char *a_seed = NULL;
  unsigned char hmac_hash[20] = { 0 };

  if (count <= 0)
    return -1;

  a_seed = (unsigned char*)malloc(20 + seed_len);
  if (!a_seed)
    return -1;
  memset(a_seed, 0, 20 + seed_len);

  for (loop = 0; loop < count; loop++)
  {
    if (loop == 0)
      hmac_sha1(secret, secret_len, seed, seed_len, a);   //A(0)->A(1);
    else
      hmac_sha1(secret, secret_len, a, 20, a);            //A(i)->A(i+1);

    memcpy(a_seed, a, 20);
    memcpy(a_seed + 20, seed, seed_len);

    hmac_sha1(secret, secret_len, a_seed, 20 + seed_len, hmac_hash);
    memcpy(out + loop * 20, hmac_hash, 20 < outlen - loop * 20 ? 20 : outlen - loop * 20);
  }

  if (a_seed) free(a_seed);
  return count;
}

int p_md5(unsigned char *secret, int secret_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen)
{
  int loop = 0;
  int count = (outlen + 16 - 1) / 16;
  unsigned char a[16] = { 0 };
  unsigned char *a_seed = NULL;
  unsigned char hmac_hash[16] = { 0 };

  if (count <= 0)
    return -1;

  a_seed = (unsigned char*)malloc(16 + seed_len);
  if (!a_seed)
    return -1;
  memset(a_seed, 0, 16 + seed_len);

  for (loop = 0; loop < count; loop++)
  {
    if (loop == 0)
      hmac_md5(secret, secret_len, seed, seed_len, a);    //A(0)->A(1);
    else
      hmac_md5(secret, secret_len, a, 16, a);             //A(i)->A(i+1);

    memcpy(a_seed, a, 16);
    memcpy(a_seed + 16, seed, seed_len);

    hmac_md5(secret, secret_len, a_seed, 16 + seed_len, hmac_hash);
    memcpy(out + loop * 16, hmac_hash, 16 < outlen - loop * 16 ? 16 : outlen - loop * 16);
  }

  if (a_seed) free(a_seed);
  return count;
}

int __tls_prf(unsigned char *secret, int secret_len, unsigned char *label, int label_len, unsigned char *seed, int seed_len, unsigned char *out, unsigned int outlen)
{
  int ret = 0;
  int loop = 0;
  unsigned char *out_sha1 = NULL;
  unsigned char *out_md5 = NULL;
  unsigned char *label_seed = NULL;

  out_sha1 = (unsigned char*)malloc(outlen);
  if (!out_sha1)
    goto EndP;
  memset(out_sha1, 0, outlen);
  out_md5 = (unsigned char*)malloc(outlen);
  if (!out_md5)
    goto EndP;
  memset(out_md5, 0, outlen);

  label_seed = (unsigned char*)malloc(label_len + seed_len);
  if (!label_seed)
    goto EndP;
  memset(label_seed, 0, label_len + seed_len);

  memcpy(label_seed, label, label_len);
  memcpy(label_seed + label_len, seed, seed_len);
  ret = p_sha1(secret, (secret_len + 1) / 2, label_seed, label_len + seed_len, out_sha1, outlen);
  if (ret == -1)
    goto EndP;
  ret = p_md5(secret + secret_len / 2, (secret_len + 1) / 2, label_seed, label_len + seed_len, out_md5, outlen);
  if (ret == -1)
    goto EndP;

  for (loop = 0; loop < outlen; loop++)
    out[loop] = out_sha1[loop] ^ out_md5[loop];

  if (label_seed) free(label_seed);
  if (out_md5) free(out_md5);
  if (out_sha1) free(out_sha1);
  return 0;
EndP:
  if (label_seed) free(label_seed);
  if (out_md5) free(out_md5);
  if (out_sha1) free(out_sha1);
  return -1;
}

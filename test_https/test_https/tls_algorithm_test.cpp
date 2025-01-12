#include <string.h>
#include <openssl/ssl.h>
#include <openssl\evp.h>
#include <openssl\bio.h>
#include <openssl\kdf.h>

#define ECDH_SIZE 33

void handleErrors()
{
  printf("Error occurred.\n");
}
static void disp(const char *str, const void *pbuf, const int size)
{
  int i = 0;
  if (str != NULL){
    printf("%s:\n", str);
  }
  if (pbuf != NULL && size > 0){
    for (i = 0; i < size; i++)
      printf("%02x ", *((unsigned char *)pbuf + i));
    putchar('\n');
  }
  putchar('\n');
}

static EC_KEY *genECDHpubkey_byset(unsigned char *retpubkey, const char *pubkey, const char *prikey)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  const EC_GROUP *group = EC_KEY_get0_group(ecdh);
  EC_POINT*  p = EC_POINT_new(group);
  EC_POINT_hex2point(group, pubkey, p, NULL);
  // EC_POINT_oct2point(group, p, pubkey, ECDH_SIZE, NULL);
  EC_KEY_set_public_key(ecdh, p);

  //const char prikey[] = "ff82019154470699086128524248488673846867876336512717";
  BIGNUM* tnum = NULL;
  BN_hex2bn(&tnum, prikey);
  EC_KEY_set_private_key(ecdh, tnum);

  printf("pubkey %s\r\n", pubkey);
  //disp("prikey", prikey, prilen);

  EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, retpubkey, 1024, NULL);
  //memset(retpubkey, 0, 1024);
  //EC_POINT_point2oct(group, p, POINT_CONVERSION_COMPRESSED, retpubkey, 1024, NULL);

  printf("prikey %s\r\n", prikey);
  return ecdh;
}

static EC_KEY *genECDHtemppubkey(unsigned char *pubkey)
{
  int publen = 0;
  int prilen = 0;

  //Generate Public
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_generate_key(ecdh);

  const EC_POINT *point_pubkey = EC_KEY_get0_public_key(ecdh);
  const EC_GROUP *group = EC_KEY_get0_group(ecdh);

  //unsigned char* buf = NULL;
  //char* str = EC_POINT_point2hex(group, point_pubkey, POINT_CONVERSION_COMPRESSED, NULL);
  //EC_POINT_point2buf(group, point_pubkey, POINT_CONVERSION_COMPRESSED, &buf, NULL);
  if (0 == (publen = EC_POINT_point2oct(group, point_pubkey, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL)))
    handleErrors();
  printf("len=%d\n", publen);
  disp("pubkey", pubkey, publen);

  const BIGNUM *prinum = EC_KEY_get0_private_key(ecdh);
  unsigned char *prikey = (unsigned char*)malloc(ECDH_SIZE);
  prilen = BN_bn2bin(prinum, prikey);//BN_bn2hex(prinum);
  printf("len=%d\n", prilen);
  disp("prikey", prikey, prilen);


  free(prikey);
  return ecdh;
}

static unsigned char *genECDHsharedsecret(EC_KEY* self_ecdh, const char *ServerPubkey, int* outlen)
{
  //unsigned char *peerkey = NULL;
  //int remote_publen = 0;
  //{
  //  unsigned char *remote_pubkey = (unsigned char*)malloc(1024);
  //  const EC_POINT *point_pubkey = EC_KEY_get0_public_key(remote_ecdh);
  //  const EC_GROUP *remote_group = EC_KEY_get0_group(remote_ecdh);
  //  if (0 == (remote_publen = EC_POINT_point2oct(remote_group, point_pubkey, POINT_CONVERSION_UNCOMPRESSED, remote_pubkey, 1024, NULL)))
  //    handleErrors();
  //  printf("len=%d\n", remote_publen);
  //  disp("romte_pubkey", remote_pubkey, remote_publen);
  //  peerkey = remote_pubkey;
  //} 

  //ComputeKey
  const EC_GROUP *group = EC_KEY_get0_group(self_ecdh);
  EC_POINT *t_point = EC_POINT_new(group);
  EC_POINT_hex2point(group, ServerPubkey, t_point, NULL);
  //EC_POINT_oct2point(group, point_peer, peerpubkey, peerpubkey_len, NULL);

  unsigned char *outbuf = (unsigned char *)malloc(128);
  int len = ECDH_compute_key(outbuf, 128, t_point, self_ecdh, NULL);
  if (0 == len)
    handleErrors();
  printf("len=%d\n", len);
  *outlen = len;
  disp("shared", outbuf, len);
  return outbuf;
}

int pre_master(char* client_pubkey, char* client_prikey, char* server_pubkey, unsigned char* out, int* outlen) {
  unsigned char *keydata1 = (unsigned char*)malloc(1024);
  //EC_KEY *ecdh = genECDHtemppubkey(keydata);

  //unsigned char *keydata2 = (unsigned char*)malloc(1024);
  //EC_KEY *ecdh2 = genECDHtemppubkey(keydata2);

  //char client_pubkey[] = "032c603e123d0cada3fdb68b60e63fb62de23448c9d2b3ecf151ce275c47849342";
  //char client_pubkey[] = "04c573d2a2afe874a1940ff0f414e06ed7ab2a0eeb076e2e41bed76345828e46bb3d4e24add2a4eef531e4ed8b2f19f8e7a560f3f22e8ec0c4508847d6ba946b2d";
  //char client_prikey[] = "17a5af48e470db83eac5a2bfae2cfa921710f5de46e155c8874da6959010b9dc";


  //char server_pubkey[] = "048637f9286a452fe540adef9bcb8650c4298315f15964e2398b9d41707cf6c7ede0a758f4b8f3f99965dc448168e14ae6ea580f59fe877756e9ab8d4837a4d126";
  //char prikey2[] = "021e14b0d2d8c8afefb899a6a4de4453702e0b327e53b9ec1cdf6d96133f49c2181111111";

  EC_KEY *ecdh1 = genECDHpubkey_byset(keydata1, client_pubkey, client_prikey);
  unsigned char *ECDH_keydata1 = genECDHsharedsecret(ecdh1, server_pubkey, outlen);
  memcpy(out, ECDH_keydata1, *outlen);
  //EC_KEY *ecdh2 = genECDHpubkey_byset(keydata2, pubkey2, prikey2);
  //unsigned char *ECDH_keydata2 = genECDHsharedsecret(ecdh2, pubkey1);

  printf("To the end\n");
  free(keydata1);
  //free(keydata2);
  EC_KEY_free(ecdh1);
  //EC_KEY_free(ecdh2);
  free(ECDH_keydata1);
  //free(ECDH_keydata2);
  return 0;
}


//t1_enc.c 
int tls1_prf(SSL *s,
  const void *seed1, size_t seed1_len,
  const void *seed2, size_t seed2_len,
  const void *seed3, size_t seed3_len,
  const void *seed4, size_t seed4_len,
  const void *seed5, size_t seed5_len,
  const unsigned char *sec, size_t slen,
  unsigned char *out, size_t olen, int fatal)
{
  const EVP_MD *md = EVP_md5_sha1(); //ssl_prf_md(s);
  EVP_PKEY_CTX *pctx = NULL;
  int ret = 0;

  if (md == NULL) {
    /* Should never happen */
    //if (fatal)
    //  SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS1_PRF,
    //  ERR_R_INTERNAL_ERROR);
    //else
    //  SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
  if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
    || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
    || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0
    || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0
    || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0
    || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0
    || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0
    || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0
    || EVP_PKEY_derive(pctx, out, &olen) <= 0) {
    //if (fatal)
    //  SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS1_PRF,
    //  ERR_R_INTERNAL_ERROR);
    //else
    //  SSLerr(SSL_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

void test() //Cipher Suite : TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014)
{  
  unsigned char client_random[32] = {
      0xFB, 0x5A, 0x4C, 0x31, 0xDD, 0x68, 0xA3, 0xF7, 0x18, 0x90, 0x76, 0x30, 0x84, 0xFC, 0x67, 0x29,
      0xCF, 0x2D, 0x4D, 0xFF, 0x67, 0x5A, 0xD6, 0xE0, 0xEB, 0xA2, 0xB5, 0x85, 0x6E, 0x5E, 0x2D, 0x06
    };
  unsigned char server_random[32] = {
      0x60, 0x65, 0x2C, 0xC2, 0x38, 0x8F, 0x8D, 0x9C, 0x15, 0x95, 0x16, 0x0A, 0xE7, 0x28, 0x0D, 0x71,
      0xEB, 0x9E, 0x41, 0xD9, 0x74, 0xC9, 0x89, 0xA2, 0x53, 0xC6, 0xEA, 0x61, 0xBD, 0xC5, 0x1B, 0x13
    };

  char client_pubkey[] = "04e2e4bae8cdb2c490c0c726be547a6f56ee15c8619e93fb797bac8f39121eef035c12347d54a3b0bceec160d50169d8e12c3fb9379e454a6334ac5acfb39bd4f3"; //首字节04 表示未压缩
  char client_prikey[] = "cf7ecb07029934ce8e8eaf723ab695e5b63b8d79a5abade83ef05f8e34cac95e";

  char server_pubkey[] = "04d2d797af21bfd3dae2e23edaca34e9c1d41846aaecd317fd8b57ecc870bfe4fd437594045bbae76456cb78847a43aade76abe2f1f5f54b97bc6a27e171432568";

  unsigned char per_masterkey[512];
  memset(per_masterkey, 0, 512);
  int perLen = 0;

  pre_master(client_pubkey, client_prikey, server_pubkey, per_masterkey, &perLen); //ecdhe  secp256r1  预主共享密钥 计算  h:\openssl-1.1.1j\crypto\ec\ec_kmeth.c -> ECDH_compute_key


  unsigned char hdata[1518] = {
      0x01, 0x00, 0x01, 0x1C, 0x03, 0x03, 0xFB, 0x5A, 0x4C, 0x31, 0xDD, 0x68, 0xA3, 0xF7, 0x18, 0x90,
      0x76, 0x30, 0x84, 0xFC, 0x67, 0x29, 0xCF, 0x2D, 0x4D, 0xFF, 0x67, 0x5A, 0xD6, 0xE0, 0xEB, 0xA2,
      0xB5, 0x85, 0x6E, 0x5E, 0x2D, 0x06, 0x20, 0x68, 0x9E, 0x34, 0xF9, 0x25, 0x04, 0xB7, 0xC5, 0x6C,
      0xC7, 0xA1, 0xD9, 0x70, 0xA5, 0x5F, 0xC8, 0xFD, 0x9A, 0xCA, 0xDD, 0x17, 0x4D, 0x67, 0x0D, 0x4B,
      0x68, 0x50, 0x4F, 0x9A, 0xEF, 0x67, 0x3B, 0x00, 0x3E, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xC0,
      0x2C, 0xC0, 0x30, 0x00, 0x9F, 0xCC, 0xA9, 0xCC, 0xA8, 0xCC, 0xAA, 0xC0, 0x2B, 0xC0, 0x2F, 0x00,
      0x9E, 0xC0, 0x24, 0xC0, 0x28, 0x00, 0x6B, 0xC0, 0x23, 0xC0, 0x27, 0x00, 0x67, 0xC0, 0x0A, 0xC0,
      0x14, 0x00, 0x39, 0xC0, 0x09, 0xC0, 0x13, 0x00, 0x33, 0x00, 0x9D, 0x00, 0x9C, 0x00, 0x3D, 0x00,
      0x3C, 0x00, 0x35, 0x00, 0x2F, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x95, 0x00, 0x0B, 0x00, 0x04, 0x03,
      0x00, 0x01, 0x02, 0x00, 0x0A, 0x00, 0x0C, 0x00, 0x0A, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x1E, 0x00,
      0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
      0x0D, 0x00, 0x30, 0x00, 0x2E, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08,
      0x09, 0x08, 0x0A, 0x08, 0x0B, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06,
      0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02, 0x05,
      0x02, 0x06, 0x02, 0x00, 0x2B, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01,
      0x00, 0x2D, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20,
      0x15, 0x15, 0x30, 0x1E, 0x1B, 0xEA, 0xA5, 0x1C, 0x13, 0xCC, 0x25, 0x74, 0x4B, 0xA7, 0xD5, 0xA9,
      0xA7, 0x42, 0x18, 0x3B, 0x48, 0xBC, 0x61, 0x33, 0xD6, 0x64, 0x97, 0x8B, 0xA2, 0x68, 0xCF, 0x21,
      0x02, 0x00, 0x00, 0x51, 0x03, 0x01, 0x60, 0x65, 0x2C, 0xC2, 0x38, 0x8F, 0x8D, 0x9C, 0x15, 0x95,
      0x16, 0x0A, 0xE7, 0x28, 0x0D, 0x71, 0xEB, 0x9E, 0x41, 0xD9, 0x74, 0xC9, 0x89, 0xA2, 0x53, 0xC6,
      0xEA, 0x61, 0xBD, 0xC5, 0x1B, 0x13, 0x20, 0x18, 0x1B, 0x00, 0x00, 0xD0, 0xF2, 0x97, 0x2F, 0x12,
      0xD7, 0xE6, 0xA1, 0x97, 0x12, 0xF5, 0xB9, 0x28, 0x42, 0x56, 0x9D, 0x1A, 0x0F, 0x0F, 0xEB, 0xE8,
      0x64, 0x0F, 0x38, 0x38, 0xFD, 0x72, 0x2F, 0xC0, 0x14, 0x00, 0x00, 0x09, 0x00, 0x17, 0x00, 0x00,
      0xFF, 0x01, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x02, 0xE0, 0x00, 0x02, 0xDD, 0x00, 0x02, 0xDA, 0x30,
      0x82, 0x02, 0xD6, 0x30, 0x82, 0x01, 0xBE, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x6D, 0x5C,
      0xB8, 0xEF, 0xBE, 0xB4, 0xA6, 0xB5, 0x4C, 0x04, 0xDF, 0x5A, 0x86, 0x37, 0xD0, 0x6A, 0x30, 0x0D,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x14, 0x31,
      0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x46, 0x61, 0x6E, 0x67, 0x59, 0x48,
      0x2D, 0x50, 0x43, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x33, 0x31, 0x34, 0x31, 0x34, 0x31,
      0x39, 0x30, 0x35, 0x5A, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x33, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x5A, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09,
      0x46, 0x61, 0x6E, 0x67, 0x59, 0x48, 0x2D, 0x50, 0x43, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06,
      0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F,
      0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xE1, 0x0B, 0x0B, 0x88, 0x6F, 0x07,
      0x0D, 0x2E, 0xBA, 0x2A, 0x91, 0x47, 0x4F, 0xC2, 0x70, 0x9C, 0xA4, 0xB4, 0x8E, 0xE0, 0x6C, 0x9B,
      0x34, 0x99, 0xAF, 0x7F, 0xC9, 0x62, 0x1A, 0x26, 0x4B, 0x70, 0x23, 0x40, 0xE2, 0x82, 0xFE, 0x9F,
      0x83, 0xC2, 0xE3, 0xBA, 0xC8, 0xCA, 0x33, 0x60, 0xE2, 0x1B, 0xE1, 0x28, 0x80, 0x1D, 0x6C, 0xB7,
      0xD5, 0xDF, 0x1E, 0x11, 0xC5, 0xDE, 0xE2, 0xC0, 0x38, 0x93, 0x44, 0x9E, 0x1D, 0x3B, 0xEF, 0x2E,
      0xCA, 0x39, 0x0B, 0xF8, 0xD7, 0x1B, 0x19, 0xE2, 0x54, 0x26, 0xD9, 0xD3, 0x9C, 0xD4, 0xA2, 0x7E,
      0x3A, 0xC7, 0x7D, 0x3C, 0x94, 0xE8, 0xE3, 0xAC, 0xA6, 0xF3, 0x35, 0x34, 0x21, 0x47, 0xB2, 0xDE,
      0xF6, 0xF4, 0x58, 0x1C, 0x2D, 0x36, 0x7C, 0x85, 0xD0, 0x6D, 0x3A, 0xAF, 0xBA, 0x6A, 0xFD, 0xA1,
      0xAF, 0x22, 0x47, 0x25, 0x78, 0x5B, 0xB6, 0x98, 0x44, 0xC3, 0x29, 0x8F, 0x12, 0x49, 0x69, 0x0E,
      0x17, 0xD5, 0xE7, 0x96, 0xE5, 0x05, 0xAB, 0x0D, 0xE8, 0x3F, 0xE8, 0x43, 0x42, 0x3B, 0x62, 0x7B,
      0xD4, 0x8F, 0x0E, 0x36, 0xC3, 0x17, 0x42, 0x30, 0x66, 0xB6, 0xD7, 0xCA, 0xA0, 0x9C, 0x86, 0xF6,
      0x89, 0xA4, 0x86, 0x8C, 0xE1, 0xB4, 0xC1, 0x60, 0x47, 0x35, 0x52, 0x49, 0x15, 0x15, 0xA2, 0x34,
      0x17, 0x4C, 0x7C, 0x98, 0x07, 0xD7, 0x98, 0x70, 0x4D, 0x33, 0xF5, 0x10, 0x4A, 0x71, 0x51, 0x16,
      0xF2, 0x2A, 0x3B, 0xCF, 0xB2, 0x2C, 0xFC, 0xF1, 0x2D, 0xBD, 0xCE, 0xC2, 0x77, 0x23, 0x93, 0x9E,
      0x16, 0xBE, 0xFD, 0x1C, 0x31, 0xFA, 0x1A, 0xBF, 0x2C, 0x89, 0xDF, 0x2F, 0x1B, 0x01, 0x8A, 0x20,
      0x74, 0x91, 0x0D, 0xAB, 0x1B, 0x7D, 0xE8, 0x0D, 0x12, 0x26, 0x34, 0xE4, 0xA2, 0x0E, 0xA1, 0x78,
      0x72, 0x0B, 0x95, 0x2C, 0x8B, 0xF2, 0xC0, 0x7C, 0xF1, 0x67, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3,
      0x24, 0x30, 0x22, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x04, 0x30,
      0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
      0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xD7, 0x73, 0xD2, 0xA7, 0x3B, 0xAB, 0x72,
      0xF7, 0x8F, 0x75, 0xAF, 0x4D, 0x87, 0x18, 0x80, 0xC0, 0x3F, 0xF9, 0x3E, 0x54, 0xFB, 0x3A, 0x9F,
      0xCA, 0x11, 0x11, 0x45, 0x9B, 0xC4, 0xC3, 0x2E, 0x87, 0x79, 0x56, 0x77, 0x22, 0x51, 0x30, 0x86,
      0xF9, 0x2E, 0xCC, 0xB8, 0x12, 0x8E, 0xC5, 0x05, 0x8A, 0x00, 0x32, 0xE4, 0x59, 0x2E, 0xD6, 0x81,
      0xB5, 0xA3, 0x56, 0x0C, 0xB1, 0x03, 0xE2, 0x0C, 0x6E, 0x3D, 0x7C, 0x4F, 0x3F, 0x7A, 0x6F, 0xD4,
      0x0A, 0x5A, 0x1B, 0x29, 0x1D, 0x8D, 0xF9, 0x3E, 0x21, 0x7F, 0x70, 0xBA, 0x23, 0x70, 0x29, 0xBF,
      0xCD, 0xF2, 0x0A, 0x75, 0x21, 0xD4, 0x81, 0x58, 0x5D, 0x4E, 0xE7, 0x50, 0x31, 0xA6, 0xDC, 0xD3,
      0xB5, 0x7F, 0x73, 0xDC, 0xB5, 0xFD, 0xCE, 0x70, 0x05, 0x64, 0x98, 0xBC, 0x55, 0xAF, 0xEE, 0x9A,
      0x4C, 0xD4, 0x4B, 0x64, 0x2E, 0x70, 0x7E, 0x7B, 0x38, 0x26, 0xBD, 0xB8, 0xEB, 0xED, 0xF3, 0xE1,
      0x89, 0x27, 0xF8, 0x2E, 0x98, 0xF9, 0xFE, 0x5F, 0xF4, 0x7A, 0xC1, 0x45, 0x21, 0x65, 0x46, 0xE2,
      0xA1, 0xC2, 0xFC, 0xAE, 0x2F, 0x08, 0x59, 0x22, 0x7C, 0x75, 0xB1, 0xA0, 0xC9, 0xC7, 0x26, 0x6B,
      0xE6, 0x64, 0x4D, 0x69, 0x5B, 0x32, 0x1F, 0x83, 0xE1, 0xFC, 0x4D, 0xFA, 0x48, 0x79, 0xCE, 0x66,
      0x08, 0xB3, 0xF7, 0x7A, 0x70, 0xCF, 0x53, 0xB3, 0x90, 0x56, 0xCC, 0xDB, 0x7B, 0xD3, 0xCE, 0xDF,
      0xC9, 0xCA, 0xA9, 0xEC, 0xCF, 0xB3, 0x64, 0x0B, 0x1A, 0xE1, 0xB2, 0x25, 0xFD, 0x9D, 0x0C, 0x82,
      0x0E, 0xC4, 0x09, 0xE0, 0xBD, 0xAA, 0x77, 0xA1, 0x50, 0xA4, 0xC7, 0x5C, 0x9B, 0x11, 0x44, 0x58,
      0x60, 0x34, 0x83, 0x65, 0x24, 0x94, 0xA5, 0x6D, 0x93, 0xAF, 0x13, 0x52, 0xBF, 0xBB, 0x11, 0xE6,
      0x93, 0x5A, 0xD8, 0x4D, 0xA6, 0x3C, 0x63, 0x89, 0x7B, 0x0C, 0x00, 0x01, 0x47, 0x03, 0x00, 0x17,
      0x41, 0x04, 0xD2, 0xD7, 0x97, 0xAF, 0x21, 0xBF, 0xD3, 0xDA, 0xE2, 0xE2, 0x3E, 0xDA, 0xCA, 0x34,
      0xE9, 0xC1, 0xD4, 0x18, 0x46, 0xAA, 0xEC, 0xD3, 0x17, 0xFD, 0x8B, 0x57, 0xEC, 0xC8, 0x70, 0xBF,
      0xE4, 0xFD, 0x43, 0x75, 0x94, 0x04, 0x5B, 0xBA, 0xE7, 0x64, 0x56, 0xCB, 0x78, 0x84, 0x7A, 0x43,
      0xAA, 0xDE, 0x76, 0xAB, 0xE2, 0xF1, 0xF5, 0xF5, 0x4B, 0x97, 0xBC, 0x6A, 0x27, 0xE1, 0x71, 0x43,
      0x25, 0x68, 0x01, 0x00, 0x06, 0x37, 0xB6, 0x98, 0x1D, 0x29, 0xAC, 0xEF, 0x78, 0x50, 0x4B, 0x71,
      0xF2, 0xF7, 0x76, 0x6B, 0x8B, 0xE1, 0xCD, 0xBE, 0x14, 0xDC, 0x4E, 0x16, 0x52, 0xF7, 0x43, 0x31,
      0x7A, 0x06, 0x4D, 0x5D, 0x86, 0xE9, 0x38, 0xFF, 0xDF, 0x9F, 0x0D, 0x0C, 0xB0, 0xEF, 0x4F, 0x26,
      0x47, 0x1C, 0x96, 0x05, 0xAF, 0x22, 0xB8, 0x03, 0x6F, 0x41, 0xC8, 0x2E, 0xAC, 0xEF, 0x32, 0xC4,
      0xC3, 0xA0, 0x17, 0x1E, 0x60, 0xB2, 0x6C, 0x82, 0x79, 0xAA, 0x42, 0xCF, 0x59, 0xDC, 0xE7, 0x78,
      0x84, 0x69, 0x67, 0x8E, 0x4F, 0x11, 0x5A, 0x23, 0x86, 0x47, 0xE0, 0xF2, 0xC9, 0x3E, 0xE9, 0xCA,
      0x57, 0x2F, 0x63, 0xFA, 0x57, 0xE8, 0xCC, 0x23, 0x7E, 0x75, 0xCE, 0x49, 0xCD, 0xA1, 0xEF, 0x65,
      0x21, 0xF3, 0x79, 0x4D, 0xD4, 0xD8, 0x08, 0x53, 0xC6, 0x78, 0x5B, 0xDE, 0x12, 0xDD, 0xEA, 0xD6,
      0x19, 0x9A, 0xD6, 0xB9, 0xAD, 0x81, 0x45, 0xF1, 0xDD, 0x01, 0xDA, 0xC4, 0x2D, 0x2B, 0x2C, 0x2D,
      0xBB, 0xA8, 0xDF, 0x96, 0xF4, 0x12, 0x1F, 0x76, 0x95, 0x26, 0x1B, 0x1D, 0x96, 0xE7, 0x7D, 0xD4,
      0x98, 0x8B, 0xA4, 0x2F, 0xD6, 0x15, 0x03, 0x0B, 0x8D, 0xCD, 0xE8, 0x1E, 0x51, 0x4F, 0xED, 0xCE,
      0x67, 0x45, 0xDB, 0x15, 0x0C, 0xFD, 0xC7, 0xF1, 0x75, 0x21, 0xE3, 0x0F, 0xAD, 0xDA, 0xDC, 0x81,
      0xF2, 0xBF, 0x76, 0x07, 0x88, 0x53, 0xC7, 0x5F, 0xFC, 0x3F, 0xA1, 0x9A, 0x16, 0x45, 0xF5, 0x8E,
      0x2D, 0x7F, 0xCF, 0x02, 0xFE, 0xB6, 0x8C, 0x54, 0x5E, 0xA1, 0x18, 0xE5, 0x06, 0x8A, 0x1E, 0x10,
      0x70, 0x1C, 0x3B, 0xDC, 0xE5, 0x2A, 0xC4, 0xEA, 0xEC, 0xDC, 0xA8, 0x7B, 0x4D, 0x6C, 0xD1, 0xC5,
      0xDC, 0x23, 0x96, 0x95, 0x10, 0x45, 0xCD, 0x73, 0x59, 0x55, 0x35, 0x08, 0xF3, 0xFE, 0x1B, 0xD4,
      0x35, 0x50, 0x7C, 0xCC, 0x0E, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x42, 0x41, 0x04, 0xE2, 0xE4,
      0xBA, 0xE8, 0xCD, 0xB2, 0xC4, 0x90, 0xC0, 0xC7, 0x26, 0xBE, 0x54, 0x7A, 0x6F, 0x56, 0xEE, 0x15,
      0xC8, 0x61, 0x9E, 0x93, 0xFB, 0x79, 0x7B, 0xAC, 0x8F, 0x39, 0x12, 0x1E, 0xEF, 0x03, 0x5C, 0x12,
      0x34, 0x7D, 0x54, 0xA3, 0xB0, 0xBC, 0xEE, 0xC1, 0x60, 0xD5, 0x01, 0x69, 0xD8, 0xE1, 0x2C, 0x3F,
      0xB9, 0x37, 0x9E, 0x45, 0x4A, 0x63, 0x34, 0xAC, 0x5A, 0xCF, 0xB3, 0x9B, 0xD4, 0xF3
    };
  unsigned char hashout[512];
  size_t olen = 48;
  const EVP_MD *md = EVP_md5_sha1();
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, hdata, 0x5ee);
  EVP_DigestFinal_ex(mdctx, hashout, NULL); //主共享密钥计算，所需参数hash计算  计算握手包hash  h:\openssl-1.1.1j\ssl\t1_enc.c -> tls1_generate_master_secret -> ssl_handshake_hash


  unsigned char master_key[512];
  memset(master_key, 0, 512);
  tls1_prf(NULL,
    TLS_MD_EXTENDED_MASTER_SECRET_CONST,
    TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE,
    hashout, 36,
    NULL, 0,
    NULL, 0,
    NULL, 0, per_masterkey, 32, master_key,
    SSL3_MASTER_SECRET_SIZE, 1);              //主共享密钥计算  h:\openssl-1.1.1j\ssl\t1_enc.c -> tls1_generate_master_secret

  unsigned char keyblock[512];
  memset(keyblock, 0, 512);
  tls1_prf(NULL,
    TLS_MD_KEY_EXPANSION_CONST,
    TLS_MD_KEY_EXPANSION_CONST_SIZE, 
    server_random,SSL3_RANDOM_SIZE, 
    client_random, SSL3_RANDOM_SIZE,
    NULL, 0,
    NULL, 0, master_key, 48, keyblock,
    0x88, 1);                             //最终 对称加密密钥块计算 h:\openssl-1.1.1j\ssl\t1_enc.c -> tls1_generate_key_block
}

/*
Handshake:
01 00 01 1c 03 03 a9 bb d9 04 85 a8 be 24 01 44
e1 8e 2d 48 53 f3 32 31 9b 64 7b 0a af 2a 94 a6
31 9f ac a4 96 bd 20 47 63 7e 60 35 d7 0a 41 90
d5 3f 94 ab 39 c4 63 88 6b 94 0a 48 cc 22 0e 7c
6f 4e 3a a2 8c 6c 6c 00 3e 13 02 13 03 13 01 c0
2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00
9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0
14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00
3c 00 35 00 2f 00 ff 01 00 00 95 00 0b 00 04 03
00 01 02 00 0a 00 0c 00 0a 00 1d 00 17 00 1e 00
19 00 18 00 23 00 00 00 16 00 00 00 17 00 00 00
0d 00 30 00 2e 04 03 05 03 06 03 08 07 08 08 08
09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06
01 03 03 02 03 03 01 02 01 03 02 02 02 04 02 05
02 06 02 00 2b 00 09 08 03 04 03 03 03 02 03 01
00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20
b2 79 dc 70 b2 33 7d 82 7d 9f 8d 30 c6 e0 af 2e
ac cc ce 56 92 fc 43 c9 e3 1c 00 43 b6 6c 3a 45
02 00 00 51 03 01 60 64 8f c6 fd 91 b5 d2 3a a9
44 ba eb d7 c7 8f 66 09 64 fa f0 6c bd 1c 3b cc
6f 4b 31 83 b0 49 20 17 19 00 00 e5 c3 1d 87 d2
bc a1 d5 63 ae 91 79 97 7a 70 d4 93 b8 95 52 d5
a8 00 ef d7 f1 63 e7 c0 14 00 00 09 00 17 00 00
ff 01 00 01 00 0b 00 02 e0 00 02 dd 00 02 da 30
82 02 d6 30 82 01 be a0 03 02 01 02 02 10 6d 5c
b8 ef be b4 a6 b5 4c 04 df 5a 86 37 d0 6a 30 0d
06 09 2a 86 48 86 f7 0d 01 01 05 05 00 30 14 31
12 30 10 06 03 55 04 03 13 09 46 61 6e 67 59 48
2d 50 43 30 1e 17 0d 32 31 30 33 31 34 31 34 31
39 30 35 5a 17 0d 32 32 30 33 31 34 30 30 30 30
30 30 5a 30 14 31 12 30 10 06 03 55 04 03 13 09
46 61 6e 67 59 48 2d 50 43 30 82 01 22 30 0d 06
09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f
00 30 82 01 0a 02 82 01 01 00 e1 0b 0b 88 6f 07
0d 2e ba 2a 91 47 4f c2 70 9c a4 b4 8e e0 6c 9b
34 99 af 7f c9 62 1a 26 4b 70 23 40 e2 82 fe 9f
83 c2 e3 ba c8 ca 33 60 e2 1b e1 28 80 1d 6c b7
d5 df 1e 11 c5 de e2 c0 38 93 44 9e 1d 3b ef 2e
ca 39 0b f8 d7 1b 19 e2 54 26 d9 d3 9c d4 a2 7e
3a c7 7d 3c 94 e8 e3 ac a6 f3 35 34 21 47 b2 de
f6 f4 58 1c 2d 36 7c 85 d0 6d 3a af ba 6a fd a1
af 22 47 25 78 5b b6 98 44 c3 29 8f 12 49 69 0e
17 d5 e7 96 e5 05 ab 0d e8 3f e8 43 42 3b 62 7b
d4 8f 0e 36 c3 17 42 30 66 b6 d7 ca a0 9c 86 f6
89 a4 86 8c e1 b4 c1 60 47 35 52 49 15 15 a2 34
17 4c 7c 98 07 d7 98 70 4d 33 f5 10 4a 71 51 16
f2 2a 3b cf b2 2c fc f1 2d bd ce c2 77 23 93 9e
16 be fd 1c 31 fa 1a bf 2c 89 df 2f 1b 01 8a 20
74 91 0d ab 1b 7d e8 0d 12 26 34 e4 a2 0e a1 78
72 0b 95 2c 8b f2 c0 7c f1 67 02 03 01 00 01 a3
24 30 22 30 0b 06 03 55 1d 0f 04 04 03 02 04 30
30 13 06 03 55 1d 25 04 0c 30 0a 06 08 2b 06 01
05 05 07 03 01 30 0d 06 09 2a 86 48 86 f7 0d 01
01 05 05 00 03 82 01 01 00 d7 73 d2 a7 3b ab 72
f7 8f 75 af 4d 87 18 80 c0 3f f9 3e 54 fb 3a 9f
ca 11 11 45 9b c4 c3 2e 87 79 56 77 22 51 30 86
f9 2e cc b8 12 8e c5 05 8a 00 32 e4 59 2e d6 81
b5 a3 56 0c b1 03 e2 0c 6e 3d 7c 4f 3f 7a 6f d4
0a 5a 1b 29 1d 8d f9 3e 21 7f 70 ba 23 70 29 bf
cd f2 0a 75 21 d4 81 58 5d 4e e7 50 31 a6 dc d3
b5 7f 73 dc b5 fd ce 70 05 64 98 bc 55 af ee 9a
4c d4 4b 64 2e 70 7e 7b 38 26 bd b8 eb ed f3 e1
89 27 f8 2e 98 f9 fe 5f f4 7a c1 45 21 65 46 e2
a1 c2 fc ae 2f 08 59 22 7c 75 b1 a0 c9 c7 26 6b
e6 64 4d 69 5b 32 1f 83 e1 fc 4d fa 48 79 ce 66
08 b3 f7 7a 70 cf 53 b3 90 56 cc db 7b d3 ce df
c9 ca a9 ec cf b3 64 0b 1a e1 b2 25 fd 9d 0c 82
0e c4 09 e0 bd aa 77 a1 50 a4 c7 5c 9b 11 44 58
60 34 83 65 24 94 a5 6d 93 af 13 52 bf bb 11 e6
93 5a d8 4d a6 3c 63 89 7b 0c 00 01 47 03 00 17
41 04 99 b1 86 27 81 c2 3c 10 0f 0a d0 c1 0f e5
62 e7 b4 b7 a9 ff 8a ed 58 ae 3f 06 78 ad b6 38
fd 03 f2 ef 55 bc e8 d4 55 0c da 90 8e 16 99 90
f5 1f e8 fc 0d 07 ac 06 b5 5a 6e 73 71 c3 fd 7e
52 78 01 00 88 5d bf 6b 94 22 17 04 a4 eb 5d 77
66 f9 06 8c 00 67 12 8f 99 71 38 f2 74 29 b1 7a
c1 ff b5 19 9c 2d 28 94 c2 65 5d 8c d2 46 12 4f
f4 25 f0 4a ac 34 58 00 69 30 72 df 10 25 7e 2b
50 20 b8 67 29 32 2e b0 67 c4 a6 7b 16 91 cd 54
4c 4c 90 12 0d 08 95 ea 39 2a a5 31 e3 1c e8 50
5c 24 62 52 8b 50 fb 51 2c fc 0f 64 5c 9c e5 cf
0a 68 21 48 c9 d7 bf 2a 82 8d 3d d2 45 34 1f 3b
df 7d 74 e6 e2 a4 48 76 67 64 7e 73 4c b9 de ed
e8 df 1a 69 e7 2c 3c be 77 76 1d 37 ef 35 ba a1
82 37 33 73 6b 1b 5f 28 0f 37 a3 56 11 33 bc 57
4b 62 5e 38 7e b4 5b ef 6a 2e 17 65 7f 10 6a e3
bb ed 3a 7e fb 77 a2 96 3d 6c db 82 48 3c c5 3f
1f c4 a8 fc 8e 0b b8 71 66 90 15 ce 2e 32 35 60
89 40 6e ac 55 2b 9f 47 fc 25 2c 0a 10 99 0e 25
34 57 3c 57 ca ab 8c e4 2c ab f0 be 56 84 ad 61
af 8d 89 54 0e 00 00 00 10 00 00 42 41 04 da 8f
0b c4 90 60 05 3d 11 ec dc 28 03 98 f6 dd 6e f9
57 8b a5 62 78 f8 26 c6 90 5c 77 b5 b7 0a 0a c7
43 ef 85 02 d0 9f ee 9b 61 6e 65 8c b1 6b 48 13
37 12 60 59 0a 5a 49 9c 0e a8 86 5f 57 64
len=65
Client pubkey
04 da 8f 0b c4 90 60 05 3d 11 ec dc 28 03 98 f6
dd 6e f9 57 8b a5 62 78 f8 26 c6 90 5c 77 b5 b7
0a 0a c7 43 ef 85 02 d0 9f ee 9b 61 6e 65 8c b1
6b 48 13 37 12 60 59 0a 5a 49 9c 0e a8 86 5f 57
64
len=32
Client prikey
64 d6 86 f8 4f 19 f6 88 af cf 11 97 4e f0 02 4f
11 08 4e 32 70 b3 be 09 3a 6b 91 fd 6c db 70 a0
len=65
Server pubkey
04 99 b1 86 27 81 c2 3c 10 0f 0a d0 c1 0f e5 62
e7 b4 b7 a9 ff 8a ed 58 ae 3f 06 78 ad b6 38 fd
03 f2 ef 55 bc e8 d4 55 0c da 90 8e 16 99 90 f5
1f e8 fc 0d 07 ac 06 b5 5a 6e 73 71 c3 fd 7e 52
78
Handshake hashes:
0000 - d8 a6 3c 86 d2 52 a1 84-39 ce 90 54 7b 64 72 d9   ..<..R..9..T{dr.
0010 - ff a7 2f 5e 59 9e a3 cf-ea bf e6 fc 30 7a fd c7   ../^Y.......0z..
0020 - 7a 80 86 72                                       z..r
Premaster Secret:
0000 - 65 9f 6f 1d aa 5d 18 e6-ef 34 82 dc d5 2c 7b 90   e.o..]...4...,{.
0010 - 2b c0 fc 7b 7e e3 35 63-d7 4e 89 58 52 88 86 ca   +..{~.5c.N.XR...
Client Random:
0000 - a9 bb d9 04 85 a8 be 24-01 44 e1 8e 2d 48 53 f3   .......$.D..-HS.
0010 - 32 31 9b 64 7b 0a af 2a-94 a6 31 9f ac a4 96 bd   21.d{..*..1.....
Server Random:
0000 - 60 64 8f c6 fd 91 b5 d2-3a a9 44 ba eb d7 c7 8f   `d......:.D.....
0010 - 66 09 64 fa f0 6c bd 1c-3b cc 6f 4b 31 83 b0 49   f.d..l..;.oK1..I
Master Secret:
0000 - 90 63 cc 48 02 d3 7c b9-43 65 0b a7 53 f0 44 2f   .c.H..|.Ce..S.D/
0010 - 3f 82 a3 b3 76 3e 82 c2-6e 51 90 7d 2e 8e ec 92   ?...v>..nQ.}....
0020 - 86 d2 6c 79 be 5f b0 f2-7b 9b 03 13 27 72 89 f1   ..ly._..{...'r..
*/
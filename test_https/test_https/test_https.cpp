// test_https.cpp : 定义控制台应用程序的入口点。
//

// Mercedes-BenzXentryFileDecrypt.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <tchar.h>
#include <Windows.h>
#include <string> 
using namespace std;

#include <openssl\aes.h>
#include <openssl\des.h>
#include <openssl\ssl3.h>
#include <openssl\rand.h>
#include <openssl\err.h>
#include <openssl\ec.h>

extern "C"
{
#include <openssl/applink.c>
};
#pragma comment(lib,"ws2_32.lib")
char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
  LPSTR pszOut = NULL;
  if (lpwszStrIn != NULL)
  {
    int nInputStrLen = wcslen(lpwszStrIn);

    // Double NULL Termination  
    int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;
    pszOut = new char[nOutputStrLen];

    if (pszOut)
    {
      memset(pszOut, 0x00, nOutputStrLen);
      WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
    }
  }
  return pszOut;
}

void TaTa_Access(unsigned char pInBuf[16], unsigned char pOutBuf[16])
{
  //unsigned char pInBuf[16] = {
  //	0x02, 0x02, 0x02, 0x02,
  //	0x02, 0x02, 0x02, 0x02,
  //	0x02, 0x02, 0x02, 0x02,
  //	0x02, 0x02, 0x02, 0x03 };

  char* key = "KEYDIAGTATA0X101";
  int inSize = 16;
  AES_KEY aes;
  if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
  {
    return;
  }
  AES_encrypt((unsigned char*)pInBuf, (unsigned char*)pOutBuf, &aes);
}

void AES_Test(unsigned char ppOutBuf[16])
{
  char* str = "40CB059818D1866875ABAFDAF496FFC9299885E32F1AEF957DE580BA0CE07F5A87D0A5B9027035A97169A77A95362D9F6EF5D84974EE13C4903F2590E7EE3852E427A7B9F5B35F1F398B732307F3EB1AD517BE97A269BF72348723D66598E5C4906FEB83384D7BE3EB9B14CE2F2DFC0B2FF854A4D81475A082544DFEF4FE33D0CD8CF1BA3BECE1B8B38BEC30CA4DB581EB47DC50E49731E667DF08D5D9A02BC421E95990234B16FE1B2698C47581191B230EA87ADB69FF6B05871A2EE02B9CFF07CF42117D559EB52CA90390891B696268CEE30A818827FACFE85582975BE62DE393F44450BD36CF3ECBAD12BD832A4AF64855DAB3CE819381B9B2FEF698DCFF783A491E23F02C1A369D4F904D1CB47189FC5095BAF4170DFEA074801B14E6393377C6C9DD79554382F0C68C018F98D5796C63BC57ADF114649CC93F0768E6A6798969D5652ED2CE2E9373799EAB02081E633F1884BEF31F2C84B82470062AE41CD1886264376ADD4DBA765469DB7EB3751056522075C898ABD99AC32534DE99DFF2A0F73627E40D89EC313D33057CCAA7E69D639F8CB1423E88E8438C23A60207CF42117D559EB52CA90390891B696268CEE30A818827FACFE85582975BE62DC3E7C6204F3CEA56DA6A6566533415B95BF77770B1BF80FC0AFF1D7E6A3BE36E1DB1DA542E4C0554CF3D3D7FBD0FA46AC40F72218DA851062E3965B9F4D4DF08A97DE8D9AC7D253415BD2881419C71BE4F9FDA47CD3C9B7B5B00435ECCE998D40EDBA17FE4293FFB7573516C7D45291ED75C46BDE1375C94C9605A7E27353D67D71D2BB1BA18F756667FC293B1C05F714A0A3AE2B5B8E759927111D0A9D539E7768934D44A842752702179359E043161045A36DB34343C40C31E923A2C5903A253EE78784F0054E40174F0E5FC2F5DBA3EFC7CED31C8626CDDFC525AEB704BCA21B7BBBCDD142D15A321FAB4FD4AF599";
  unsigned char pInBuf[688];
  unsigned char pOutBuf[688];
  for (size_t i = 0; i < strlen(str) / 2; i++)
  {
    char t[4];
    t[0] = str[i * 2];
    t[1] = str[i * 2 + 1];
    t[2] = 0;

    pInBuf[i] = (unsigned char)strtol(t, NULL, 16);
  }

  //unsigned char key[32] = { 0x59, 0x53, 0x30, 0x30, 0x54, 0x57, 0x38, 0x65, 0x56, 0x32, 0x64, 0x36, 0x40, 0x61, 0x64, 0x39, 0x15, 0x46, 0x76, 0x46, 0x51, 0x06, 0x3e, 0x5b, 0x44, 0x76, 0x12, 0x24, 0x44, 0x25, 0x41, 0x78 };
  //   memset(key,0,16);
  //   strcpy(key, "YTV@SW");

  char* key = "YTV@SW2a08dd0e69"; //"YS00 TW8e V2d6 @ad9";  YS00 TW8e V2d6 @ad9

  AES_KEY aes;
  if (AES_set_decrypt_key((unsigned char*)pInBuf, 128, &aes) < 0)
  {
    return;
  }

  AES_decrypt(pInBuf, pOutBuf, &aes);

  int aa = 0;

  /* unsigned char key[] =
  {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };

  unsigned char pInBuf[] = {
  0xB5, 0x02, 0xA9, 0x00, 0x23, 0x07, 0xA4, 0x41,
  0xF8, 0x04, 0x3D, 0x03, 0x68, 0x9B, 0x69, 0x98
  };
  pInBuf[6] = 4;



  AES_KEY aes;
  if (AES_set_encrypt_key((unsigned char*)key, 256, &aes) < 0)
  {
  return;
  }

  AES_encrypt((unsigned char*)pInBuf, (unsigned char*)pOutBuf, &aes);

  unsigned char pOut[16];
  pInBuf[6] = 0xA4;
  AES_encrypt((unsigned char*)pInBuf, (unsigned char*)pOutBuf + 20, &aes);*/
}

void CharToHex(char* pSrc, int nLen, char* pDes);

int getPagesHttps(const char* host_addr, const int host_port, const char* pObject)
{
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 0), &wsaData);

  SOCKET sockfd;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    printf("Socket Error: %s", strerror(errno));
    return -1;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(host_port);
  server_addr.sin_addr.s_addr = inet_addr(host_addr);

  if (connect(sockfd, (struct sockaddr *) (&server_addr), sizeof(struct sockaddr)) == -1)
  {
    printf("Connect Error: %s\n", strerror(errno));
    return -1;
  }

  SSL *ssl;
  SSL_CTX *ctx;
  // SSL initialize
  SSL_library_init();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(SSLv23_client_method());
  if (ctx == NULL)
  {
    printf("SSL CTX new failed!");
    return -1;
  }

  ssl = SSL_new(ctx);
  if (ssl == NULL)
  {
    printf("SSL new failed!");

    return -1;
  }

  // link socket & SSL
  int ret = SSL_set_fd(ssl, sockfd);
  if (ret == 0)
  {
    printf("SSL link socket failed!");

    return -1;
  }


  RAND_poll();
  while (RAND_status() == 0)
  {
    unsigned short rand_ret = rand() % 65536;
    RAND_seed(&rand_ret, sizeof(rand_ret));
  }
   
  // SSL connect
  ret = SSL_connect(ssl);
  if (ret != 1)
  {
    printf("SSL connect failed!");

    return -1;
  }

  printf("Connected with %s encryption\r\n", SSL_get_cipher(ssl));
  unsigned char out[128];
  memset(out, 0, 128);
  int nnlen = SSL_get_server_random(ssl, out, 128);
  char buf[256];
  memset(buf, 0, 256);
  CharToHex((char*)out, nnlen, buf);
  //SSL_write(ssl, out, nnlen);
  //Sleep(2000);
  //int send = SSL_write(ssl, ssl->, senMsage.length());
  // send https request
  string senMsage = "GET HTTPS://10.8.0.2/ HTTP/1.1\r\n";
  senMsage += "Host: 10.8.0.2\r\n";
  senMsage += "Connection: Keep-Alive\r\n";
  senMsage += "Cache-Control: max-age=0\r\n";
  senMsage += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
  senMsage += "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36\r\n";
  senMsage += "Accept-Encoding: gzip,deflate,sdch\r\n";
  senMsage += "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n";
  senMsage += "server_random: ";
  senMsage += buf;
  senMsage += "\r\n\r\n";

  printf("%s\r\n", senMsage.c_str());
  printf("***********\r\n");

  int send = SSL_write(ssl, senMsage.c_str(),senMsage.length());
  if (send == -1)
  {
    printf("SSL send failed!\r\n");
  }
  printf("%d bytes send OK!\r\n", send);


  // receive https response
  
#define MAX 2*5000
  Sleep(4000);
  char returnBuffer[MAX];
  memset(returnBuffer, 0, MAX);

  int responseLen = SSL_read(ssl, returnBuffer, MAX);
  responseLen += SSL_read(ssl, returnBuffer + responseLen, MAX);


  printf("#############responseLen: %d\r\n", responseLen);
  printf("returnBuffer: ->%s\r\n", returnBuffer);
  printf("#############\r\n");

  Sleep(2000);
  // shutdown community 
  ret = SSL_shutdown(ssl);
  printf("shutdown %d\r\n", ret);
  if (ret != 1)
  {
    printf("SSL shutdown failed!\r\n");
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  ERR_free_strings();
  closesocket(sockfd);
  WSACleanup();
  return 0;
}

int testaes()
{
  unsigned char in[48] = {
    0x14, 0x00, 0x00, 0x0C, 0x97, 0xAC, 0x98, 0x53, 0xC0, 0xA6, 0x14, 0xEA, 0xB8, 0x9F, 0x0B, 0xAC,
    0xF4, 0xE9, 0x8D, 0x4B, 0xE8, 0x5A, 0x8C, 0x79, 0x78, 0x80, 0xA4, 0x81, 0xF2, 0xDA, 0x42, 0xBF,
    0xF5, 0x8D, 0x07, 0x76, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B
  };

  unsigned char iv[16] = {
    0xE1, 0x19, 0xA7, 0x8D, 0x95, 0x4E, 0xCE, 0xE4, 0x72, 0x9E, 0xF5, 0x2A, 0xF0, 0xDB, 0x12, 0xE6
  };
  unsigned char key[32] = {
    0x06, 0x5B, 0xC1, 0x1A, 0x2F, 0x55, 0x2A, 0xA3, 0x5F, 0x55, 0xDF, 0x8D, 0x72, 0x22, 0x2A, 0x84,
    0x7D, 0x09, 0x88, 0xCF, 0x2E, 0xCC, 0xC0, 0xE2, 0xAE, 0xBC, 0x8C, 0xB2, 0xB8, 0x88, 0x58, 0x84
  };
  unsigned int* num = (unsigned int*)key;
  num[0] = num[0] >> 24 | num[0] << 24 | num[0] << 8 & 0xFF0000 | num[0] >> 8 & 0xFF00;
  num[1] = num[1] >> 24 | num[1] << 24 | num[1] << 8 & 0xFF0000 | num[1] >> 8 & 0xFF00;
  num[2] = num[2] >> 24 | num[2] << 24 | num[2] << 8 & 0xFF0000 | num[2] >> 8 & 0xFF00;
  num[3] = num[3] >> 24 | num[3] << 24 | num[3] << 8 & 0xFF0000 | num[3] >> 8 & 0xFF00;
  num[4] = num[4] >> 24 | num[4] << 24 | num[4] << 8 & 0xFF0000 | num[4] >> 8 & 0xFF00;
  num[5] = num[5] >> 24 | num[5] << 24 | num[5] << 8 & 0xFF0000 | num[5] >> 8 & 0xFF00;
  num[6] = num[6] >> 24 | num[6] << 24 | num[6] << 8 & 0xFF0000 | num[6] >> 8 & 0xFF00;
  num[7] = num[7] >> 24 | num[7] << 24 | num[7] << 8 & 0xFF0000 | num[7] >> 8 & 0xFF00;

  unsigned char buf_encrypt[64] = "";
  unsigned char buf_decrypt[64] = "";
  AES_KEY aesKey;
  AES_set_encrypt_key(key, 256, &aesKey);
  AES_cbc_encrypt(in, buf_encrypt, 48, &aesKey, iv, 1);

  //unsigned char key[320] = "1234567812345678123456781234567811111111111111111111111111";
  //unsigned char iv[16] = "123456";
  //unsigned char iv_copy[16];
  //unsigned char testdata[64] = "加解密测试明文字符串";
  //unsigned char buf_encrypt[64] = "";
  //unsigned char buf_decrypt[64] = "";
  //AES_KEY aesKey;

  ////加密
  //memcpy(iv_copy, iv, 16);//向量在运算过程中会被改变，为了之后可以正常解密，拷贝一份副本使用
  //AES_set_encrypt_key(key, 256, &aesKey);
  //AES_cbc_encrypt(testdata, buf_encrypt, sizeof(testdata), &aesKey, iv_copy, 1);

  ////解密
  //memcpy(iv_copy, iv, 16);
  //AES_set_decrypt_key(key, 256, &aesKey);
  //AES_cbc_encrypt(buf_encrypt, buf_decrypt, sizeof(buf_encrypt), &aesKey, iv_copy, 0);
  return 0;
}

char *my_pub_encrypt(char *str, char *pubkey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *en = NULL;
  int len = 0;
  int rsa_len = 0;

  if ((fp = fopen(pubkey_path, "r")) == NULL) {
    return NULL;
  }

  /* 读取公钥PEM，PUBKEY格式PEM使用PEM_read_RSA_PUBKEY函数 */
  if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL) {
    return NULL;
  }

  //BIGNUM *p = *((BIGNUM**)((int)rsa + 16));
  //char * number_str = BN_bn2hex(p);
  //printf("%s\n", number_str);
  
  RSA_print_fp(stdout, rsa, 0);

  len = strlen(str);
  rsa_len = RSA_size(rsa);

  en = (char *)malloc(rsa_len + 1);
  memset(en, 0, rsa_len + 1);

  if (RSA_public_encrypt(rsa_len, (unsigned char *)str, (unsigned char*)en, rsa, RSA_NO_PADDING) < 0) {
    return NULL;
  }

  RSA_free(rsa);
  fclose(fp);

  return en;
}


char *my_pub_decrypt(char *str, char *pubkey_path, int* pdeLen)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *de = NULL;
  int rsa_len = 0;

  if ((fp = fopen(pubkey_path, "r")) == NULL) {
    return NULL;
  }

  if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL) {
    return NULL;
  }

  RSA_print_fp(stdout, rsa, 0);

  rsa_len = RSA_size(rsa);
  de = (char *)malloc(rsa_len + 1);
  memset(de, 0, rsa_len + 1);

  int delen = RSA_public_decrypt(rsa_len, (unsigned char *)str, (unsigned char*)de, rsa, RSA_PKCS1_PADDING);
  if (delen < 0) {
    return NULL;
  }
  *pdeLen = delen;
  RSA_free(rsa);
  fclose(fp);

  return de;
}

char *my_pri_encrypt(char *str, char *prikey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *en = NULL;
  int len = 0;
  int rsa_len = 0;

  if ((fp = fopen(prikey_path, "r")) == NULL) {
    return NULL;
  }

  /* 读取公钥PEM，PUBKEY格式PEM使用PEM_read_RSA_PUBKEY函数 */
  if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
    return NULL;
  }

  BIGNUM *p = *((BIGNUM**)((int)rsa + 16));
  char * number_str = BN_bn2hex(p);
  printf("%s\n", number_str);

  RSA_print_fp(stdout, rsa, 0);

  len = strlen(str);
  rsa_len = RSA_size(rsa);

  en = (char *)malloc(rsa_len + 1);
  memset(en, 0, rsa_len + 1);

  if (RSA_private_encrypt(rsa_len, (unsigned char *)str, (unsigned char*)en, rsa, RSA_NO_PADDING) < 0) {
    return NULL;
  }

  RSA_free(rsa);
  fclose(fp);

  return en;
}

char *my_pri_decrypt(char *str, char *prikey_path)
{
  RSA *rsa = NULL;
  FILE *fp = NULL;
  char *de = NULL;
  int rsa_len = 0;

  if ((fp = fopen(prikey_path, "r")) == NULL) {
    return NULL;
  }

  if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
    return NULL;
  }

  RSA_print_fp(stdout, rsa, 0);

  rsa_len = RSA_size(rsa);
  de = (char *)malloc(rsa_len + 1);
  memset(de, 0, rsa_len + 1);

  if (RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char*)de, rsa, RSA_NO_PADDING) < 0) {
    return NULL;
  }

  RSA_free(rsa);
  fclose(fp);

  return de;
}

struct MyStruct
{
  int t1;
  int t2;
  BIGNUM* X;
  BIGNUM* Y;
  BIGNUM* Z;
};
struct MyStruct1
{
  MyStruct* pub_key;
  BIGNUM* priv_key;
};
struct Myec
{
  int ary[4];
  MyStruct1 x_pk;
};
int show_big(BIGNUM* n)
{
  char * number_str = BN_bn2hex(n);
  printf("%s\n", number_str);
  return 0;
}
int show()
{
  Myec* ec = (Myec*)0xffff;
  MyStruct1 *p = &ec->x_pk;

  show_big(p->pub_key->X);
  show_big(p->pub_key->Y);
  show_big(p->pub_key->Z);
  show_big(p->priv_key);
  
  return 0;
}
int MY_EC_KEY_generate_key(EC_KEY *key)
{
  int(*EC_KEY_generate_key_fun)(EC_KEY *key) = EC_KEY_generate_key;
  printf("fdsa\r\n");
  return 0;
}
int testbignum()
{
  static const
    char p_str[] = "ff82019154470699086128524248488673846867876336512717";

  BIGNUM *p = BN_new();
  BN_hex2bn(&p, p_str);

  char * number_str = BN_bn2hex(p);
  printf("%s\n", number_str);

  OPENSSL_free(number_str);
  BN_free(p);
  
  return 0;
}

static const char hexdig[] = "0123456789abcdef";
void HexToChar(char * pSrc, int nLen, char * pDes)
{
  int i;
  int j = 0;
  for (i = 0; i<nLen; i++)
  {
    //高4位
    if (pSrc[i] >= 0x30 && pSrc[i] <= 0x39)
    {
      pDes[j] = (pSrc[i] - 0x30) << 4;
    }
    else
    {
      pDes[j] = (pSrc[i] - 0x41 + 10) << 4;
    }

    //低4位
    i++;
    if (pSrc[i] >= 0x30 && pSrc[i] <= 0x39)
    {
      pDes[j++] |= (pSrc[i] - 0x30);
    }
    else
    {
      pDes[j++] |= (pSrc[i] - 0x41 + 10);
    }
  }
}

void CharToHex(char* pSrc, int nLen, char* pDes)
{
  char hexDigit[] = "0123456789ABCDEF";
  int i;
  int j = 0;
  for (i = 0; i< nLen; i++)
  {
    //高4位
    pDes[j++] = hexDigit[(pSrc[i] >> 4) & 0x0F];
    //低4位
    pDes[j++] = hexDigit[pSrc[i] & 0x0F];
  }
}

void log_hex(const char* tag, unsigned char* data, int len){
  char msg[50], *ptr;
  int i;
  ptr = msg;

  printf("%s\r\n", tag);
  for (i = 0; i<len; i++) {
    *ptr++ = hexdig[0x0f & (data[i] >> 4)];
    *ptr++ = hexdig[0x0f & data[i]];
    if ((i & 0x0f) == 0x0f) {
      *ptr = '\0';
      ptr = msg;
      printf("%s\r\n", msg);
    }
    else {
      *ptr++ = ' ';
    }
  }
  if (i & 0x0f) {
    *ptr = '\0';
    printf("%s\r\n", msg);
  }
}
int rsa_Signature()
{
  unsigned char sig[256] = {
    0x6E, 0xB8, 0x74, 0x6A, 0xF4, 0x85, 0xB9, 0xEF, 0xD7, 0x5A, 0x3D, 0x00, 0x6C, 0xBE, 0x76, 0x4A,
    0x0B, 0x1F, 0x65, 0xA5, 0x0E, 0x48, 0x86, 0x4D, 0x82, 0xB6, 0x7F, 0xAB, 0xC5, 0x50, 0xEE, 0x11,
    0xAC, 0xED, 0x25, 0x6C, 0x05, 0xE8, 0x9A, 0x06, 0x6D, 0xE6, 0x3C, 0x0E, 0xB9, 0x5E, 0x78, 0x2B,
    0x78, 0x29, 0x75, 0x0F, 0xAC, 0x64, 0x79, 0xF5, 0xCC, 0x20, 0xB4, 0x61, 0x8D, 0x29, 0x14, 0x71,
    0x58, 0xD8, 0xC9, 0x1C, 0x56, 0x10, 0xEB, 0x0F, 0xDC, 0xB4, 0x09, 0x1C, 0xF8, 0x3F, 0x7A, 0xE7,
    0x46, 0xC0, 0x9A, 0xCF, 0x13, 0xE7, 0x63, 0x20, 0x98, 0xAA, 0x99, 0x0A, 0xE8, 0xB5, 0x36, 0xF3,
    0x45, 0x2E, 0x3F, 0x48, 0xED, 0x3C, 0x12, 0x8F, 0xBC, 0x73, 0xA8, 0xA4, 0xD9, 0xF4, 0x8F, 0x69,
    0x67, 0xD0, 0xC7, 0x8D, 0xC0, 0x02, 0x12, 0xFF, 0x56, 0x48, 0x28, 0xA1, 0x07, 0x41, 0xE5, 0x8F,
    0xF0, 0x5C, 0xA0, 0x0A, 0x4A, 0x60, 0xE4, 0xC2, 0x57, 0xE0, 0xAF, 0x6C, 0xDC, 0x11, 0x6A, 0xB7,
    0x1F, 0x45, 0x46, 0xC2, 0x15, 0xDF, 0xFC, 0x60, 0x32, 0x99, 0x26, 0xD9, 0x2E, 0x2A, 0x29, 0xCF,
    0xC8, 0x6F, 0x3A, 0x8B, 0xAE, 0xA7, 0x95, 0x57, 0x7F, 0x78, 0x48, 0xB6, 0x47, 0x98, 0x42, 0x47,
    0x6D, 0x78, 0x7A, 0x3C, 0x88, 0x73, 0x9C, 0xDF, 0x3F, 0x91, 0x50, 0x6C, 0xA1, 0xD3, 0x75, 0xC4,
    0x19, 0xC0, 0x45, 0x9D, 0xCB, 0xBC, 0x7C, 0x3F, 0x26, 0xA6, 0xBA, 0x11, 0x83, 0xDA, 0x25, 0xA3,
    0xDE, 0x13, 0x12, 0x96, 0xA4, 0x9E, 0x88, 0x94, 0x21, 0x94, 0x31, 0x06, 0xE2, 0xAA, 0x7B, 0xF8,
    0x9B, 0x4B, 0x0C, 0xDD, 0x02, 0xA3, 0xC3, 0x48, 0xB3, 0x95, 0xB6, 0xF3, 0xAC, 0xA4, 0xF8, 0x26,
    0x0B, 0x36, 0x3A, 0xA7, 0xC1, 0x00, 0x3D, 0xE8, 0x4F, 0x45, 0x9A, 0x09, 0x25, 0xFC, 0xE7, 0x55
  };
  int len = 0;
  char* sde = my_pub_decrypt((char*)sig, "pubkey.pem", &len);
  log_hex("dec: ", (unsigned char*)sde, len);

  return 0;
  //39 a1 6d b0 77 6f 35 70 74 25 bf 1f f7 1c 22 28
  //44 ac 0a 95 f6 33 90 72 c2 43 f5 76 78 1a 78 7d
  //fc 41 7f 78
}
int testrsa()
{ 
  rsa_Signature();
  return 0;


  char *src = "hello, world!";
  char *en = NULL;
  char *de = NULL;

  printf("src is: %s\n", src);

  en = my_pub_encrypt(src, "pubkey.pem");
  printf("enc is: %s\n", en);

  de = my_pri_decrypt(en, "prikey.pem");
  printf("dec is: %s\n", de);

  if (en != NULL) {
    free(en);
  }

  if (de != NULL) {
    free(de);
  }
  return 0;
}
int showkey ()
{
  unsigned char pubkey[1024];
  int publen = 0;
  int prilen = 0;

  EC_KEY *ecdh = NULL;

  const EC_POINT *point_pubkey = EC_KEY_get0_public_key(ecdh);
  const EC_GROUP *group = EC_KEY_get0_group(ecdh);

  if (0 == (publen = EC_POINT_point2oct(group, point_pubkey, POINT_CONVERSION_UNCOMPRESSED, pubkey, 1024, NULL)))
    printf("err\r\n");
  printf("len=%d\n", publen);
  log_hex("pubkey", pubkey, publen);

  const BIGNUM *prinum = EC_KEY_get0_private_key(ecdh);
  unsigned char *prikey = (unsigned char*)malloc(33);
  prilen = BN_bn2bin(prinum, prikey);//BN_bn2hex(prinum);
  printf("len=%d\n", prilen);
  log_hex("prikey", prikey, prilen);


  free(prikey);
  return 0;
}

int testECDHE();
int xx();
void test();
int server();
int _tmain(int argc, _TCHAR* argv[])
{
  if (argc != 1)
  {
    server();
  }
 
  //test();
  system("pause");
  //testECDHE();
  //testbignum();
  //testrsa();
  // testaes();
  //EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  //NID_secp256k1
  // int ret = ECDH_compute_key(NULL,NULL,NULL,NULL, 0); 
  //tls1_export_keying_material
  //tls1_generate_key_block
  //if (ec == NULL)
  //  return 0;
  //EC_KEY_generate_key(ec);
  while (true)
  {
    getPagesHttps("10.8.0.2", 443, NULL);
    system("pause");
  }


  //DES_cblock key;
  ///**//* DES_random_key(&key); */ /**//* generate a random key */
  //DES_string_to_key("11111111", &key);

  //
  //DES_key_schedule schedule;
  //DES_set_key_checked(&key, &schedule);


  //unsigned char data[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
  //unsigned char key[8] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 };

  unsigned char data[32] = {
    0x55, 0x43, 0xAA, 0x78, 0xDD, 0x3F, 0x31, 0x01, 0xA3, 0x05, 0x11, 0x10, 0x0B, 0x19, 0x3D, 0x3D,
    0xDC, 0x28, 0x6E, 0x0E, 0x4A, 0x04, 0xB8, 0x7A, 0x2D, 0xAC, 0x53, 0xCD, 0x54, 0xCF, 0x99, 0x34
  };

  char* key = "&%HRY*78$9klme";

  const_DES_cblock* _key = (const_DES_cblock*)&key[0];
  const_DES_cblock* input = (const_DES_cblock*)&data[0];


  //DES_cblock output;
  //printf("cleartext:%s ", input);
  //DES_ecb_encrypt(input, &output, &schedule, DES_ENCRYPT);
  //printf("Encrypted! ");



  unsigned char temp[256] = { 0 };
  int datalen = 32;

  const_DES_cblock inbuf;
  DES_cblock outbuf;

  DES_key_schedule schedule;
  DES_set_key_unchecked(_key, &schedule);
  for (int i = 0; i < datalen / 8; i++)
  {
    memcpy(inbuf, input + i * 8, 8);
    DES_ecb_encrypt(&inbuf, &outbuf, &schedule, DES_DECRYPT); //DES_DECRYPT  DES_ENCRYPT
    memcpy(temp + i * 8, outbuf, 8);
  }


  unsigned char pOut[256];
  AES_Test(pOut);

  system("pause");
  return 0;
}


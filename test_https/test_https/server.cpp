#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <string> 
using namespace std;
//#include <unistd.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

SOCKET create_socket(int port)
{
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 0), &wsaData);

  SOCKET sockfd;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    printf("Socket Error: %s", strerror(errno));
    return -1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(443);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);// inet_addr("127.0.0.1");

  int ret = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
  if (ret == SOCKET_ERROR) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }
  if (listen(sockfd, 1) < 0) {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }
  return sockfd;
}

void init_openssl()
{
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
  EVP_cleanup();
}

SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLSv1_method();//SSLv23_server_method();

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

void configure_context(SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}
void log_hex(const char* tag, unsigned char* data, int len);
void HexToChar(char * pSrc, int nLen, char * pDes);
int server()
{
  SOCKET sock;
  SSL_CTX *ctx;

  init_openssl();
  ctx = create_context();

  configure_context(ctx);

  sock = create_socket(443);

  /* Handle connections */
  while (1) {
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SSL *ssl;
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    }
    else {
      Sleep(2000);
      printf("read: \r\n");
      unsigned char out[512];
      memset(out, 0, 512);
      int len = SSL_read(ssl, out, 512);
     // len = SSL_read(ssl, out, 512);
      printf("%s \r\n", out);

     

      string recv = (char*)out;
      int index = recv.find("server_random: ");
      string random = recv.substr(index + 15);
      random.erase( random.find("\r\n\r\n"), 4);
     
      char buf[512];
      memset(buf, 0, 512);
      HexToChar((char*)random.c_str(), random.length(), buf);

      unsigned char out1[128];
      memset(out1, 0, 128);
      int nnlen = SSL_get_server_random(ssl, out1, 128);
      log_hex("server self server_random", out1, nnlen);

      log_hex("recv client ret server_random", (unsigned char*)buf, random.length()/2);

      string senMsage = "HTTP/1.1 200 OK\r\n";
      senMsage += "Cache-Control: no-cache\r\n";
      senMsage += "Content-Type: text/html\r\n";
      senMsage += "Last-Modified: Sat, 20 Mar 2021 14:20:21 GMT\r\n";
      senMsage += "Accept-Ranges: bytes\r\n";
      
      if (memcmp(buf, out1, nnlen) != 0){
        printf("发现代理\r\n");
        senMsage += "Content-Length: 20\r\n\r\n";
        senMsage += "!!!you used proxy!!!";
      }
      else{
        senMsage += "Content-Length: 24\r\n\r\n";
        senMsage += "!!!you not used proxy!!!";
      }
     
      Sleep(2000);
      SSL_write(ssl, senMsage.c_str(), senMsage.length());
      printf("send data\r\n");
    }

    SSL_free(ssl);
    closesocket(client);
  }

  closesocket(sock);
  SSL_CTX_free(ctx);
  cleanup_openssl();
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define SERVER_PORT 55111 
/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define KEY_SIZE 32 // 256-bit key
#define IV_SIZE 16  // 128-bit IV
#define HMAC_SIZE 32


void handle_error(const char *file, int lineno, const char *msg) {
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)


/**************************************************************************
 * Encrpypt and Decrypt							     * 		*									     *
 ***************************************************************************/

void handleErrors(void)
{
  printf("Error occurred\n");
  exit(1);
}

int encrypt_aes(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_aes(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *decryptedtext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int decrypted_len;
  int ret;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
    handleErrors();
  decrypted_len = len;

  ret = EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
  if (ret > 0)
    decrypted_len += len;
  else if (ret == 0)
    printf("Decryption failed: padding is incorrect.\n");
  else
    handleErrors();

  decryptedtext[decrypted_len] = '\0'; // Add null terminator

  EVP_CIPHER_CTX_free(ctx);

  return decrypted_len;
}

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{

  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
  {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev)
  {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
  {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{

  int nread;

  if ((nread = read(fd, buf, n)) < 0)
  {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{

  int nwrite;

  if ((nwrite = write(fd, buf, n)) < 0)
  {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

  int nread, left = n;

  while (left > 0)
  {
    if ((nread = cread(fd, buf, left)) == 0)
    {
      return 0;
    }
    else
    {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

  va_list argp;

  if (debug)
  {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}


void generate_random_bytes(unsigned char *buffer, size_t length) {
    RAND_poll();
    RAND_bytes(buffer, length);
}

int main(int argc, char *argv[])
{

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
  //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, server_fd,server_net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1; /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  unsigned char key[KEY_SIZE]; //   = "01234567890123456789012345678901";
  unsigned char iv[IV_SIZE]; // = "0123456789012345";
  //unsigned char *hmac_key = key;


  progname = argv[0];

  /* Check command line options */
  while ((option = getopt(argc, argv, "i:sc:p:uahd")) > 0)
  {
    switch (option)
    {
    case 'd':
      debug = 1;
      break;
    case 'h':
      usage();
      break;
    case 'i':
      strncpy(if_name, optarg, IFNAMSIZ - 1);
      break;
    case 's':
      cliserv = SERVER;
      break;
    case 'c':
      cliserv = CLIENT;
      strncpy(remote_ip, optarg, 15);
      break;
    case 'p':
      port = atoi(optarg);
      break;
    case 'u':
      flags = IFF_TUN;
      break;
    case 'a':
      flags = IFF_TAP;
      header_len = ETH_HDR_LEN;
      break;
    default:
      my_err("Unknown option %c\n", option);
      usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0)
  {
    my_err("Too many options!\n");
    usage();
  }

  if (*if_name == '\0')
  {
    my_err("Must specify interface name!\n");
    usage();
  }
  else if (cliserv < 0)
  {
    my_err("Must specify client or server mode!\n");
    usage();
  }
  else if ((cliserv == CLIENT) && (*remote_ip == '\0'))
  {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0)
  {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        perror("SSL_CTX_new");
        return 1;
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file");
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        perror("SSL_load_verify_location");

    }

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

   ssl = SSL_new(ctx);
   if (ssl == NULL) {
      perror("SSL_new");
      SSL_CTX_free(ctx);
      return 1;
   }

 
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set up server address
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(SERVER_PORT);
    if (bind(server_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Server listening on port %d\n", SERVER_PORT);   
  
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((server_net_fd = accept(server_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
      perror("accept()");
      exit(1);
    }



   if (SSL_set_fd(ssl, server_net_fd) == 0) {
    perror("SSL_set_fd");
    SSL_free(ssl);
    close(server_net_fd); // Close the socket
    return 1;
   }


  if (SSL_accept(ssl) != 1) {
    perror("SSL_accept");
    SSL_free(ssl); // Free the SSL object in case of failure
    return 1;
   }

    printf("SSL connection established.\n");   

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Generate random key
    generate_random_bytes(key, KEY_SIZE);

    // Generate random IV
    generate_random_bytes(iv, IV_SIZE);

    // Writing key to client
    int bytes_written = SSL_write(ssl, key, KEY_SIZE);
    if (bytes_written != KEY_SIZE) {
        perror("Error writing key to client");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }
 printf("Key sent to client successfully.\n");
    // Writing IV to client
    bytes_written = SSL_write(ssl, iv, IV_SIZE);
    if (bytes_written != IV_SIZE) {
        perror("Error writing IV to client");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("IV sent to client successfully.\n");
    printf("Key and IV sent to client successfully.\n"); 


  unsigned char *hmac_key = key;


  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket()");
    exit(1);
  }

  if (cliserv == CLIENT)
  {
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
  }
  else
  {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
    {
      perror("setsockopt()");
      exit(1);
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
      perror("bind()");
      exit(1);
    }

    /* No need to accept connections in UDP */
    net_fd = sock_fd;

    do_debug("SERVER: Waiting for packets...\n");
  }

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

  while (1)
  {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR)
    {
      continue;
    }

    if (ret < 0)
    {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(tap_fd, &rd_set))
    {
      /* data from tun/tap: just read it and write it to the network */
      remotelen=sizeof(remote);
      nread = cread(tap_fd, buffer, BUFSIZE);
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      unsigned char ciphertext[BUFSIZE];
      int ciphertext_len = encrypt_aes((unsigned char *)buffer, nread, key, iv, ciphertext);

      unsigned char hmac[HMAC_SIZE];
      unsigned int hmac_len;
      HMAC(EVP_sha256(), hmac_key, KEY_SIZE, ciphertext, ciphertext_len, hmac, &hmac_len);

      /* write length + encrypted packet */
      nwrite = sendto(net_fd, (char *)&ciphertext_len, sizeof(ciphertext_len), 0, (struct sockaddr *)&remote, sizeof(remote));
      nwrite = sendto(net_fd, hmac, HMAC_SIZE, 0, (struct sockaddr *)&remote, sizeof(remote));
      nwrite = sendto(net_fd, ciphertext, ciphertext_len, 0, (struct sockaddr *)&remote, sizeof(remote));

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if (FD_ISSET(net_fd, &rd_set))
    {
      /* data from the network: read it, and write it to the tun/tap interface.
       * We need to read the length first, and then the packet */

      remotelen = sizeof(remote);

      /* Read length */
      nread = recvfrom(net_fd, (char *)&plength, sizeof(plength), 0, (struct sockaddr *)&remote, &remotelen);
      if (nread == 0)
      {
        /* ctrl-c at the other end */
        break;
      }

      net2tap++;

      unsigned char received_hmac[HMAC_SIZE];
      nread = recvfrom(net_fd, received_hmac, HMAC_SIZE, 0, (struct sockaddr *)&remote, &remotelen);

      /* read packet */
      nread = recvfrom(net_fd, buffer, ntohs(plength), 0, (struct sockaddr *)&remote, &remotelen);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      unsigned char calculated_hmac[HMAC_SIZE];
      unsigned int hmac_len;
      HMAC(EVP_sha256(), hmac_key, KEY_SIZE, buffer, nread, calculated_hmac, &hmac_len);

     if (memcmp(received_hmac, calculated_hmac, HMAC_SIZE) != 0)
      {
        printf("HMAC verification failed.\n");
        continue;
      }

      unsigned char decryptedtext[BUFSIZE];
      int decrypted_len = decrypt_aes((unsigned char *)buffer, nread, key, iv, decryptedtext);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */


      nwrite = cwrite(tap_fd, decryptedtext, decrypted_len);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }

  SSL_shutdown(ssl);
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  close(server_fd);




  return (0);
}

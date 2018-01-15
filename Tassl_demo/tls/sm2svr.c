/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All 
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

/*
 * ++
 * FACILITY:
 *
 *      Simplest SM2 TLSv1.1 Server
 *
 * ABSTRACT:
 *
 *   This is an example of a SSL server with minimum functionality.
 *    The socket APIs are used to handle TCP/IP operations. This SSL
 *    server loads its own certificate and key, but it does not verify
 *  the certificate of the SSL client.
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SM2_SERVER_CERT     "SS.pem"
#define SM2_SERVER_KEY      "SS.pem"

#define SM2_SERVER_ENC_CERT     "SE.pem"
#define SM2_SERVER_ENC_KEY      "SE.pem"

#define SM2_SERVER_CA_CERT  "CA.pem"
#define SM2_SERVER_CA_PATH  "."

#define ON   1
#define OFF  0

#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	if (!ok) {
		ok = 1;
	}

	return (ok);
}


static unsigned char *rBuffer = NULL;

int main(int argc, char **argv)
{
	int     err;
	int     verify_client = ON; /* To verify a client certificate, set ON */

	int     listen_sock;
	int     sock;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	char    *str;
	char    buf[4096];

	SSL_CTX         *ctx = NULL;
	SSL             *ssl = NULL;
	const SSL_METHOD      *meth;

	X509            *client_cert = NULL;

	short int       s_port = 4433;
	
	/*----------------------------------------------------------------*/
	if (argc > 1)
	{
		for (err = 1; err < argc; err++)
		{
			if (!strcasecmp(argv[err], "-P"))
			{
				if (argc >= (err + 2))
					s_port = atoi(argv[++err]);
				else
					s_port = 4433;
				
				if (s_port <= 0) s_port = 4433;
			}
		}
	}
	else
	{
		printf("Usage: %s [-p port]\n\t-p port: service port, default 4433\n", argv[0]);
	}

	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	meth = SSLv23_server_method();

	/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(meth);

	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SM2_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, SM2_SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
	}

	/* Load the server encrypt certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SM2_SERVER_ENC_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the server encrypt certificate */
	if (SSL_CTX_use_enc_PrivateKey_file(ctx, SM2_SERVER_ENC_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the server encrypt certificate and private-key matches */
	if (!SSL_CTX_check_enc_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
	}


	if (verify_client == ON)
	{
		/* Load the RSA CA certificate into the SSL_CTX structure */
		if (!SSL_CTX_load_verify_locations(ctx, SM2_SERVER_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx, 1);

	}
	/* ----------------------------------------------- */
	/* Set up a TCP socket */
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   

	RETURN_ERR(listen_sock, "socket");
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons(s_port);          /* Server Port number */
	err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

	RETURN_ERR(err, "bind");

	/* Wait for an incoming TCP connection. */
	err = listen(listen_sock, 5);                    

	RETURN_ERR(err, "listen");
	client_len = sizeof(sa_cli);

	/* Socket for a TCP/IP connection is created */
	sock = accept(listen_sock, (struct sockaddr *)&sa_cli, (socklen_t *)&client_len);

	RETURN_ERR(sock, "accept");
	close(listen_sock);

	printf("Connection from %lx, port %x\n",
		sa_cli.sin_addr.s_addr, 
		sa_cli.sin_port);

	/* ----------------------------------------------- */
	/* TCP connection is ready. */
	/* A SSL structure is created */
	ssl = SSL_new(ctx);

	RETURN_NULL(ssl);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, sock);

	/* Perform SSL Handshake on the SSL server */
	/*err = SSL_accept(ssl);*/
	SSL_set_accept_state(ssl);
	while (1)
	{
		err = SSL_do_handshake(ssl);
		if (err <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}
		else
			break;
	}

	RETURN_SSL(err);

	/* Informational output (optional) */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*------- DATA EXCHANGE - Receive message and send reply. -------*/
	/* Receive data from the SSL client */
	err = SSL_read(ssl, buf, sizeof(buf) - 1);

	RETURN_SSL(err);

	buf[err] = '\0';

	printf("Received %d chars:'%s'\n", err, buf);

	/* Send data to the SSL client */
	err = SSL_write(ssl,
		"-----This message is from the SSL server-----\n", 
		strlen("-----This message is from the SSL server-----\n"));

	RETURN_SSL(err);

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */

	err = SSL_shutdown(ssl);

	RETURN_SSL(err);

	/* Terminate communication on a socket */
	close(sock);

err:
	/* Free the SSL structure */
	if (ssl) SSL_free(ssl);

	/* Free the SSL_CTX structure */
	if (ctx) SSL_CTX_free(ctx);

	return 0;

	
}






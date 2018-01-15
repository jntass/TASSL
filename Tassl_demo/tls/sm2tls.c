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
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define CLIENT_S_CERT   "./CS.pem"
#define CLIENT_E_CERT   "./CE.pem"

void Init_OpenSSL()
{
    if (!SSL_library_init())
        exit(0);
    SSL_load_error_strings();
}

int seed_prng(int bytes)
{
    if (!RAND_load_file("/dev/random", bytes))
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
	BIO *conn = NULL;
	SSL *ssl = NULL;
	SSL_CTX *ctx = NULL;
	int usecert = 1;
	int retval;

	/*Detect arguments*/
	if (argc < 2)
	{
		printf("Usage : %s host:port [use_cert]\n", argv[0]);
		exit(0);
	}

	if (argc >= 3)
		usecert = atoi(argv[2]);
	
	Init_OpenSSL();

	ctx = SSL_CTX_new(CNTLS_client_method());
	if (ctx == NULL)
	{
		printf("Error of Create SSL CTX!\n");
		goto err;
	}

	if (usecert)
	{
		if (SSL_CTX_use_certificate_file(ctx, CLIENT_S_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_S_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (SSL_CTX_use_certificate_file(ctx, CLIENT_E_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (SSL_CTX_use_enc_PrivateKey_file(ctx, CLIENT_E_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (!SSL_CTX_check_private_key(ctx))
		{
			printf("Private key does not match the certificate public key/n");
			goto err;
		}

		if (!SSL_CTX_check_enc_private_key(ctx))
		{
			printf("Private key does not match the certificate public key/n");
			goto err;
		}
	}

	/*Now Connect host:port*/
	conn = BIO_new_connect(argv[1]);
	if (!conn)
	{
		printf("Error Of Create Connection BIO\n");
		goto err;
	}

	if (BIO_do_connect(conn) <= 0)
	{
		printf("Error Of Connect to %s\n", argv[1]);
		goto err;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
		printf("SSL New Error\n");
		goto err;
	}

	SSL_set_bio(ssl, conn, conn);
	/*if (SSL_connect(ssl) <= 0)
	{
	    printf("Error Of SSL connect server\n");
	    goto err;
	}*/
	SSL_set_connect_state(ssl);
	while (1)
	{
		retval = SSL_do_handshake(ssl);
		if (retval > 0)
			break;
		else
		{
			printf("Error Of SSL do handshake\n");
			goto err;
		}
	}

	if (SSL_write(ssl, "----->>>>>HELLO, My First Demo.<<<<<-----\n", 42) <= 0)
		SSL_clear(ssl);
	else
		SSL_shutdown(ssl);

err:
	if (ssl) SSL_free(ssl);
	if (ctx) SSL_CTX_free(ctx);

	return 0;

}



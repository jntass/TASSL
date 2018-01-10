/* crypto/sm3/sm3.h */
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

#ifndef SM3_HEADER_H
#define SM3_HEADER_H

#include <openssl/opensslconf.h>
#include <stddef.h>

# ifdef OPENSSL_NO_CNSM
#  error SM3 is disabled.
# endif // OPENSSL_NO_CNSM

# if defined(__LP32__)
#  define SM3_LONG unsigned long
# elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#  define SM3_LONG unsigned long
#  define SM3_LONG_LOG2 3
# else
#  define SM3_LONG unsigned int
# endif

# define SM3_DIGEST_LENGTH   32
# define SM3_LBLOCK          16
# define SM3_CBLOCK          64

struct SM3state_st
{
    SM3_LONG digest[8];
    SM3_LONG Nl, Nh;
    SM3_LONG data[SM3_LBLOCK];
    unsigned int num;
};

typedef struct SM3state_st SM3_CTX;

# ifdef __cplusplus
extern "C"
{
# endif
    int SM3_Init(SM3_CTX *c);
    int SM3_Update(SM3_CTX *c, const void *data, size_t len);
    int SM3_Final(unsigned char *md, SM3_CTX *c);
    unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md);
    void SM3_Transform(SM3_CTX *c, const unsigned char *data);
# ifdef __cplusplus
}
# endif

#endif // !SM3_HEADER_H



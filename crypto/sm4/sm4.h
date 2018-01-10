/* crypto/sm4/sm4.h */
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

#ifndef SM4_HEADER_H
#define SM4_HEADER_H

#include <openssl/opensslconf.h>

# ifdef OPENSSL_NO_CNSM
#  error SM4 is disabled.
# endif // OPENSSL_NO_CNSM

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stddef.h>

# define SM4_KEY_LENGTH           16
# define SM4_BLOCK_SIZE           16
# define SM4_IV_LENGTH            SM4_BLOCK_SIZE
# define SM4_NUM_ROUNDS           32

# define SM4_ENCRYPT              1
# define SM4_DECRYPT              0

# pragma pack(1)
struct sm4_key_st
{
    uint32_t key[SM4_NUM_ROUNDS];
};
# pragma pack()
typedef struct sm4_key_st SM4_KEY;

# ifdef __cplusplus
extern "C"
{
# endif // __cplusplus
    int SM4_set_key(const unsigned char *userKey, size_t length, SM4_KEY *key);

    void SM4_encrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key);
    void SM4_decrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key);

    void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, const int enc);
    void SM4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, const int enc);
    void SM4_cfb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num, const int enc);
    void SM4_ofb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num);
    
# ifdef __cplusplus
}
# endif // __cplusplus

#endif // SM4_HEADER_H




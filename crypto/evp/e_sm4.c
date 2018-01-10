/* crypto/evp/e_sm4.c */
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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CNSM
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/objects.h>
#include <openssl/sm4.h>
#include "evp_locl.h"

typedef struct
{
    SM4_KEY ks;
} EVP_SM4_KEY;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
    SM4_set_key(key, 16, &(dat->ks));

    return 1;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_cbc_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, ctx->encrypt);

    return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    size_t i, bl;
    bl = ctx->cipher->block_size;
    if (inl < bl)
        return 1;
    inl -= bl;
    if (ctx->encrypt)
    {
        for (i = 0; i <= inl; i += bl)
            SM4_encrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
    }
    else
    {
        for (i = 0; i <= inl; i += bl)
            SM4_decrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
    }

    return 1;
}

static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_cfb_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, &ctx->num, ctx->encrypt);

    return 1;
}

static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_ofb_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, &ctx->num);

    return 1;
}

static const EVP_CIPHER sm4_ecb = {
    NID_sm4_ecb,
    SM4_BLOCK_SIZE,
    SM4_KEY_LENGTH,
    0,
    0 | EVP_CIPH_ECB_MODE,
    sm4_init_key,
    sm4_ecb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_ecb(void)
{
    return &sm4_ecb;
}

static const EVP_CIPHER sm4_cbc = {
    NID_sm4_cbc,
    SM4_BLOCK_SIZE,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_CBC_MODE,
    sm4_init_key,
    sm4_cbc_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_cbc(void)
{
    return &sm4_cbc;
}

static const EVP_CIPHER sm4_ofb = {
    NID_sm4_ofb,
    1,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_OFB_MODE,
    sm4_init_key,
    sm4_ofb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_ofb(void)
{
    return &sm4_ofb;
}

static const EVP_CIPHER sm4_cfb = {
    NID_sm4_cfb,
    1,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_CFB_MODE,
    sm4_init_key,
    sm4_cfb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_cfb(void)
{
    return &sm4_cfb;
}

#endif



/* crypto/sm2/sm2_err.c */
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
#include <openssl/err.h>
#include <openssl/sm2.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_SM2,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_SM2,0,reason)

static ERR_STRING_DATA SM2_str_functs[] = {
    { ERR_FUNC(SM2_F_SM2_GET_Z), "ECDSA_sm2_get_Z" },
    { ERR_FUNC(SM2_F_SM2_PUB_ENCRYPT), "sm2_encrypt" },
    { ERR_FUNC(SM2_F_SM2_PRIV_DECRYPT), "sm2_decrypt" },
    { ERR_FUNC(SM2_F_SM2_CIPHER2TEXT), "i2c_sm2_enc" },
    { ERR_FUNC(SM2_F_SM2_CIPHER2STRUCTURE), "c2i_sm2_enc" },
    { ERR_FUNC(SM2_F_EC_CIPHER2TEXT), "i2c_ec_enc" },
    { ERR_FUNC(SM2_F_EC_CIPHER2STRUCTURE), "c2i_ec_enc" },
    { ERR_FUNC(SM2_F_SM2_SIGN), "sm2_do_sign" },
    { ERR_FUNC(SM2_F_SM2_VERIFY), "sm2_do_verify" },
    { ERR_FUNC(SM2_F_SM2_PREPARE), "SM2DH_prepare" },
    { ERR_FUNC(SM2_F_SM2_COMPUTE_KEY), "SM2DH_compute_key" },
    { ERR_FUNC(SM2_F_KAP_COMPUTE_KEY), "SM2Kap_compute_key" },
    { 0, NULL }
};

static ERR_STRING_DATA SM2_str_reasons[] = {
    { ERR_REASON(SM2_R_INVALID_CURVE), "invalid elliptic curve(need sm2)" },
    { ERR_REASON(SM2_R_INVALID_ARGUMENT), "invalid arguments" },
    { ERR_REASON(SM2_R_INVALID_PRIVATE_KEY), "invalid private key" },
    { ERR_REASON(SM2_R_INVALID_DIGEST), "invalid digest" },
    { ERR_REASON(SM2_R_INVALID_CIPHER_TEXT), "invalid cipher text" },
    { ERR_REASON(SM2_R_MISSING_PARAMETERS), "missing parameters" },
    { ERR_REASON(SM2_R_SIGNATURE_MALLOC_FAILED), "sm2 signature malloc failed" },
    { ERR_REASON(SM2_R_RANDOM_NUMBER_GENERATION_FAILED), "random number generator failed" },
    { ERR_REASON(SM2_R_VERIFY_MALLOC_FAILED), "sm2 verify malloc failed" },
    { ERR_REASON(SM2_R_BAD_SIGNATURE), "bad signature" },
    { ERR_REASON(SM2_R_NO_PRIVATE_VALUE), "no private value" },
    { ERR_REASON(SM2_R_EC_GROUP_NEW_BY_NAME_FAILURE), "sm2 group new by name failed" },
    { 0, NULL }
};

#endif

void ERR_load_SM2_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(SM2_str_functs[0].error) == NULL) {
        ERR_load_strings(0, SM2_str_functs);
        ERR_load_strings(0, SM2_str_reasons);
    }
#endif
}


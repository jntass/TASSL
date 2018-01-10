/* crypto/sm4/sm4.c */
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

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/sm4.h>
#include <assert.h>
#include <string.h>

//const char SM4_version[] = "SM4" OPENSSL_VERSION_PTEXT;

const uint8_t SBOX[/*256*/] = {
    /*     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F*/
    /*0*/ 0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    /*1*/ 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    /*2*/ 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    /*3*/ 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    /*4*/ 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    /*5*/ 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    /*6*/ 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    /*7*/ 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    /*8*/ 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    /*9*/ 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    /*A*/ 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    /*B*/ 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    /*C*/ 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    /*D*/ 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    /*E*/ 0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    /*F*/ 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

#define GETDWORD(A)         (((uint32_t)((A)[0]) << 24) | ((uint32_t)((A)[1]) << 16) | ((uint32_t)((A)[2]) << 8) | ((uint32_t)((A)[3])))
#define PUTDWORD(S, A)      (A)[0] = (uint8_t)(((S) >> 24) & 0xFF), (A)[1] = (uint8_t)(((S) >> 16) & 0xFF), (A)[2] = (uint8_t)(((S) >> 8) & 0xFF), (A)[3] = (uint8_t)((S) & 0xFF);

#define RSL(A, I)           (((A) << (I)) | ((A) >> (32 - (I))))

/*LC: Linear Conversion */
#define LC(A)               ((A) ^ (RSL((A), 2)) ^ (RSL((A), 10)) ^ (RSL((A), 18)) ^ (RSL((A), 24)))

/*LCK: Linear Conversion for Key Expend*/
#define LCK(A)              ((A) ^ (RSL((A), 13)) ^ (RSL((A), 23)))

/*NT: Nonlinear Transformation*/
#define NT(A)               ((SBOX[((A) >> 24)] << 24) | (SBOX[(((A) >> 16) & 0xFF)] << 16) | (SBOX[(((A) >> 8) & 0xFF)] << 8) | (SBOX[((A) & 0xFF)]))

/*RF: Round Function  RF = X0 ^ LC(NT(X1^X2^X3^RK))*/
#define RF_E(X0, X1, X2, X3, X4, RK)            X4 = (X1) ^ (X2) ^ (X3) ^ (RK), X4 = NT(X4), X4 = (X0) ^ LC(X4)

/*KERF: Key Expend Round Function K[i] = MK[i] ^ FK[i], i = 0 ~ 3; RK[i] = K[i+4] = K[i] ^ LCK(NT(K[i+1]^K[i+2]^[ki+3]^CK[i]))*/
#define KERF_K(K0, K1, K2, K3, K4, CK, RK)              K4 = (K1) ^ (K2) ^ (K3) ^ (CK), K4 = NT(K4), RK = K4 = (K0) ^ LCK(K4)

int SM4_set_key(const unsigned char *userKey, size_t length, SM4_KEY *key)
{
    uint32_t *rk = key->key;
    uint32_t K[5];

    if (length < 16)
        return 0;

    K[0] = GETDWORD(userKey) ^ 0xA3B1BAC6;
    K[1] = GETDWORD(userKey + 4) ^ 0x56AA3350;
    K[2] = GETDWORD(userKey + 8) ^ 0x677D9197;
    K[3] = GETDWORD(userKey + 12) ^ 0xB27022DC;

    KERF_K(K[0], K[1], K[2], K[3], K[4], 0x00070E15, rk[0]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0x1C232A31, rk[1]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0x383F464D, rk[2]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0x545B6269, rk[3]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0x70777E85, rk[4]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0x8C939AA1, rk[5]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0xA8AFB6BD, rk[6]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0xC4CBD2D9, rk[7]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0xE0E7EEF5, rk[8]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0xFC030A11, rk[9]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0x181F262D, rk[10]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0x343B4249, rk[11]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0x50575E65, rk[12]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0x6C737A81, rk[13]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0x888F969D, rk[14]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0xA4ABB2B9, rk[15]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0xC0C7CED5, rk[16]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0xDCE3EAF1, rk[17]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0xF8FF060D, rk[18]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0x141B2229, rk[19]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0x30373E45, rk[20]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0x4C535A61, rk[21]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0x686F767D, rk[22]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0x848B9299, rk[23]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0xA0A7AEB5, rk[24]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0xBCC3CAD1, rk[25]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0xD8DFE6ED, rk[26]);
    KERF_K(K[2], K[3], K[4], K[0], K[1], 0xF4FB0209, rk[27]);
    KERF_K(K[3], K[4], K[0], K[1], K[2], 0x10171E25, rk[28]);
    KERF_K(K[4], K[0], K[1], K[2], K[3], 0x2C333A41, rk[29]);
    KERF_K(K[0], K[1], K[2], K[3], K[4], 0x484F565D, rk[30]);
    KERF_K(K[1], K[2], K[3], K[4], K[0], 0x646B7279, rk[31]);

    return 1;
}

void SM4_encrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key)
{
    const uint32_t *rk = key->key;
    uint32_t X[5];

    assert(in && out && key);

    X[0] = GETDWORD(in);
    X[1] = GETDWORD(in + 4);
    X[2] = GETDWORD(in + 8);
    X[3] = GETDWORD(in + 12);

    RF_E(X[0], X[1], X[2], X[3], X[4], rk[0]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[1]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[2]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[3]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[4]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[5]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[6]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[7]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[8]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[9]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[10]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[11]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[12]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[13]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[14]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[15]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[16]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[17]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[18]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[19]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[20]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[21]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[22]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[23]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[24]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[25]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[26]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[27]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[28]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[29]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[30]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[31]);

    PUTDWORD(X[0], out);
    PUTDWORD(X[4], out + 4);
    PUTDWORD(X[3], out + 8);
    PUTDWORD(X[2], out + 12);

}

void SM4_decrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key)
{
    const uint32_t *rk = key->key;
    uint32_t X[5];

    assert(in && out && key);

    X[0] = GETDWORD(in);
    X[1] = GETDWORD(in + 4);
    X[2] = GETDWORD(in + 8);
    X[3] = GETDWORD(in + 12);

    RF_E(X[0], X[1], X[2], X[3], X[4], rk[31]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[30]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[29]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[28]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[27]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[26]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[25]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[24]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[23]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[22]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[21]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[20]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[19]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[18]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[17]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[16]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[15]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[14]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[13]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[12]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[11]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[10]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[9]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[8]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[7]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[6]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[5]);
    RF_E(X[2], X[3], X[4], X[0], X[1], rk[4]);
    RF_E(X[3], X[4], X[0], X[1], X[2], rk[3]);
    RF_E(X[4], X[0], X[1], X[2], X[3], rk[2]);
    RF_E(X[0], X[1], X[2], X[3], X[4], rk[1]);
    RF_E(X[1], X[2], X[3], X[4], X[0], rk[0]);

    PUTDWORD(X[0], out);
    PUTDWORD(X[4], out + 4);
    PUTDWORD(X[3], out + 8);
    PUTDWORD(X[2], out + 12);
}

void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, const int enc)
{
    size_t i = 0;
    unsigned char tails[16];

    if (enc)
    {
        while (length >= 16)
        {
            SM4_encrypt(in + i, out + i, key);
            i += 16;
            length -= 16;
        }

        if (length)
        {
            memset(tails, 0, sizeof(tails));
            memcpy(tails, in + i, length);
            SM4_encrypt((const unsigned char *)tails, out + i, key);
        }
    }
    else
    {
        while (length >= 16)
        {
            SM4_decrypt(in + i, out + i, key);
            i += 16;
            length -= 16;
        }

        if (length)
        {
            memset(tails, 0, sizeof(tails));
            memcpy(tails, in + i, length);
            SM4_decrypt((const unsigned char *)tails, out + i, key);
        }
    }
}


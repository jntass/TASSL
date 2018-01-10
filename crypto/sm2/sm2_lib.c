/* crypto/sm2/sm2_lib.c */
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

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <string.h>

const char SM2_version[] = "SM2" OPENSSL_VERSION_PTEXT;

/* GM/T003_2012 Defined Key Derive Function */
int KDF_GMT003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
    EVP_MD_CTX mctx;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;

    if (!out || !outlen) return retval;
    if (md == NULL) md = EVP_sm3();
    mdlen = EVP_MD_size(md);
    EVP_MD_CTX_init(&mctx);

    for (counter = 1;; counter++)
    {
        unsigned char dgst[EVP_MAX_MD_SIZE];

        EVP_DigestInit_ex(&mctx, md, NULL);
        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);
        if (!EVP_DigestUpdate(&mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(&mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(&mctx, SharedInfo, SharedInfolen))
            goto err;
        if (!EVP_DigestFinal(&mctx, dgst, NULL))
            goto err;

        if (outlen > mdlen)
        {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        }
        else
        {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_cleanup(&mctx);
    return retval;
}

/*Compute SM2 sign extra data: Z = HASH256(ENTL + ID + a + b + Gx + Gy + Xa + Ya)*/
int ECDSA_sm2_get_Z(const EC_KEY *ec_key, const EVP_MD *md, const char *uid, int uid_len, unsigned char *z_buf, size_t *z_len)
{
    EVP_MD_CTX *ctx;
    const EC_GROUP *group = NULL;
    BIGNUM *a = NULL, *b = NULL;
    const EC_POINT *point = NULL;
    unsigned char *z_source = NULL;
    int retval = 0;
    int deep, z_s_len;

    EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;

    if (md == NULL) md = EVP_sm3();
    if (*z_len < (size_t)md->md_size)
    {
        SM2err(SM2_F_SM2_GET_Z, SM2_R_INVALID_ARGUMENT);
        return 0;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        SM2err(SM2_F_SM2_GET_Z, SM2_R_INVALID_ARGUMENT);
        goto err;
    }

    a = BN_new(), b = BN_new();
    if ((a == NULL) || (b == NULL))
    {
        SM2err(SM2_F_SM2_GET_Z, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    if (!EC_GROUP_get_curve_GFp(group, NULL, a, b, NULL))
    {
        SM2err(SM2_F_SM2_GET_Z, ERR_R_EC_LIB);
        goto err;
    }
    
    if ((point = EC_GROUP_get0_generator(group)) == NULL)
    {
        SM2err(SM2_F_SM2_GET_Z, ERR_R_EC_LIB);
        goto err;
    }
    
    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((uid == NULL) || (uid_len <= 0))
    {
        uid = (const char *)"1234567812345678";
        uid_len = 16;
    }
   
    /*alloc z_source buffer*/
    while (!(z_source = (unsigned char *)OPENSSL_malloc(1 + 4 * deep)));

    /*ready to digest*/
    ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, md);

    z_s_len = 0;
    /*first: set the two bytes of uid bits + uid*/
    uid_len = uid_len * 8;
    
    z_source[z_s_len++] = (unsigned char)((uid_len >> 8) & 0xFF);
    z_source[z_s_len++] = (unsigned char)(uid_len & 0xFF);
    uid_len /= 8;
    EVP_DigestUpdate(ctx, z_source, z_s_len);
    EVP_DigestUpdate(ctx, uid, uid_len);

    /*second: add a and b*/
    BN_bn2bin(a, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    BN_bn2bin(b, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    
    /*third: add Gx and Gy*/
    z_s_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*forth: add public key*/
    point = EC_KEY_get0_public_key(ec_key);
    if (!point)
    {
        priv_key = EC_KEY_get0_private_key(ec_key);
        if (!priv_key)
        {
            SM2err(SM2_F_SM2_GET_Z, SM2_R_INVALID_PRIVATE_KEY);
            goto err;
        }

        pub_key = EC_POINT_new(group);
        if (!pub_key)
        {
            SM2err(SM2_F_SM2_GET_Z, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL))
        {
            SM2err(SM2_F_SM2_GET_Z, ERR_R_EC_LIB);
            goto err;
        }

        point = (const EC_POINT *)pub_key;
    }

    z_s_len = EC_POINT_point2oct(group, /*EC_KEY_get0_public_key(ec_key)*/point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*fifth: output digest*/
    EVP_DigestFinal(ctx, z_buf, (unsigned *)z_len);
    EVP_MD_CTX_destroy(ctx);
    
    retval = (int)(*z_len);

err:
    if (z_source) OPENSSL_free(z_source);
    if (pub_key) EC_POINT_free(pub_key);
    if (a) BN_free(a);
    if (b) BN_free(b);
    
    return retval;
}

/*SM2 Sign*/
ECDSA_SIG *sm2_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
    int ok = 0;
    BIGNUM *k = NULL, *e = NULL, *X = NULL, *order = NULL;
    EC_POINT *tmp_point = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *d;
    
    group = EC_KEY_get0_group(eckey);
    d = EC_KEY_get0_private_key(eckey);
    if ((group == NULL) || (d == NULL))
    {
        SM2err(SM2_F_SM2_SIGN, SM2_R_MISSING_PARAMETERS);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret)
    {
        SM2err(SM2_F_SM2_SIGN, SM2_R_SIGNATURE_MALLOC_FAILED);
        return NULL;
    }
    
    if (((ctx = BN_CTX_new()) == NULL) || ((order = BN_new()) == NULL) || ((X = BN_new()) == NULL) || ((e = BN_new()) == NULL) || ((k = BN_new()) == NULL))
    {
        SM2err(SM2_F_SM2_SIGN, SM2_R_SIGNATURE_MALLOC_FAILED);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        SM2err(SM2_F_SM2_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    if ((tmp_point = EC_POINT_new(group)) == NULL)
    {
        SM2err(SM2_F_SM2_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    
    /*if dgest_len is too long, it must be truncate*/
    if (dgst_len > 32)
        dgst_len = 32;
    
    if (!BN_bin2bn(dgst, dgst_len, e))
    {
        SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    do
    {
        /*PART I: compute r*/
        /*first: generate a random number, it must be between 1~(order - 1)*/
#ifdef TEST_SM2
        BN_hex2bn(&k, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F");
#else
        do
        {        
            if (!BN_rand_range(k, order))
            {
                SM2err(SM2_F_SM2_SIGN, SM2_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto err;
            }
        } while (BN_is_zero(k)) ;
#endif
        /*second: compute k*G*/
        if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_EC_LIB);
            goto err;
        }
        
#ifdef TEST_SM2
        printf("[line %d] Random Point: [%s]\n", __LINE__, EC_POINT_point2hex(group, tmp_point, EC_GROUP_get_point_conversion_form(group), NULL));
#endif
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
        {
            if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point, X, NULL, ctx))
            {
                SM2err(SM2_F_SM2_SIGN, ERR_R_EC_LIB);
                goto err;
            }
        }
#ifndef OPENSSL_NO_EC2M
        else
        {
            /* NID_X9_62_characteristic_two_field */
            if (!EC_POINT_get_affine_coordinates_GF2m(group, tmp_point, X, NULL, ctx))
            {
                SM2err(SM2_F_SM2_SIGN, ERR_R_EC_LIB);
                goto err;
            }
        }
#endif
        EC_POINT_free(tmp_point);

        /*third: compute r = (e + X) mod n*/
        if (!BN_mod_add(ret->r, e, X, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }

        /*and compute (r + k) mod n*/
        if (!BN_mod_add(X, ret->r, k, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }

        /*forth: detect r == 0 or r + k == n*/
        if (BN_is_zero(ret->r) || BN_is_zero(X))
            continue;
        
        /*PART II: compute s*/
        /*fifth: s = ((1 + d)^-1 * (k - rd)) mod n */
        if (!BN_one(X))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (1 + d) or (1 + d) mod n, thus need test*/        
        if (!BN_mod_add(X, d, X, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: X ** -1 mod n*/
        if (!BN_mod_inverse(ret->s, X, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: r * d mod n*/        
        if (!BN_mod_mul(X, ret->r, d, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (k - r*d) mod n*/
        if (!BN_mod_sub(X, k, X, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (((1 + d) ** -1) * (k - r * d)) mod n*/
        if (!BN_mod_mul(ret->s, ret->s, X, order, ctx))
        {
            SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(ret->s));
    
    ok = 1;    

err:
    if (!ok)
    {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx)
        BN_CTX_free(ctx);
    if (e)
        BN_clear_free(e);
    if (X)
        BN_clear_free(X);
    if (order)
        BN_free(order);
    if (k)
        BN_clear_free(k);

    return ret;
}

/*SM2 Verify*/
int sm2_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int ret = -1;
    BN_CTX *ctx;
    BIGNUM *order, *R, *x1, *e1, *t;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if ((eckey == NULL) || ((group = EC_KEY_get0_group(eckey)) == NULL) || ((pub_key = EC_KEY_get0_public_key(eckey)) == NULL) || (sig == NULL))
    {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_MISSING_PARAMETERS);
        return -1;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_VERIFY_MALLOC_FAILED);
        return -1;
    }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    e1 = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (!t)
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) || (BN_ucmp(sig->r, order) >= 0) || \
        BN_is_zero(sig->s) || BN_is_negative(sig->s) || (BN_ucmp(sig->s, order) >= 0))
    {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_BAD_SIGNATURE);
        /* signature is invalid */
        ret = 0;
        goto err;
    }

    /*if msgdigest length large to 32 then set length to 32*/
    if (dgst_len > 32)
        dgst_len = 32;
    if (!BN_bin2bn(dgst, dgst_len, e1))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    
    /*compute: t = (r1 + s1) mod n*/
    if (!BN_mod_add(t, sig->r, sig->s, order, ctx))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    
    /*detect t == 0*/
    if (BN_is_zero(t))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    
    /*compute: s1 * G + t * Pa*/
    if ((point = EC_POINT_new(group)) == NULL)
    {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_VERIFY_MALLOC_FAILED);
        goto err;
    }
    
    if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, point, x1, NULL, ctx))
        {
            SM2err(SM2_F_SM2_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x1, NULL, ctx))
        {
            SM2err(SM2_F_SM2_VERIFY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif
    
    if (!BN_nnmod(x1, x1, order, ctx))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(R, e1, x1, order, ctx))
    {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    
    /*  if the signature is correct R is equal to sig->r */
    ret = (BN_ucmp(R, sig->r) == 0);

err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);

    return ret;
}

/*SM2 Public Encrypt core function, out format is: C1 + C3 + C2*/
int __sm2_encrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    BIGNUM *k = NULL, *order = NULL, *h = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *pub_key = NULL;
    size_t loop, deep, nbytes;
    unsigned char *buf = NULL, *ckey = NULL;
    unsigned char C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;
    /*point_conversion_form_t from;*/
    int chktag;
    
    if (!outlen)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        return retval;
    }
    
    /*from = EC_GROUP_get_point_conversion_form(group);
    if ((from != POINT_CONVERSION_COMPRESSED) && (from != POINT_CONVERSION_UNCOMPRESSED) && (from != POINT_CONVERSION_HYBRID))
    {
        from = POINT_CONVERSION_UNCOMPRESSED;
    }*/
    /*from = POINT_CONVERSION_UNCOMPRESSED;*/

    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    
    /*compute outlen, it must be conside to compressed point values*/
    /*
    if (from == POINT_CONVERSION_COMPRESSED)
        nbytes = 1 + deep + inlen + md->md_size;
    else
    */
    nbytes = 1 + deep * 2 /*C1*/ + inlen + md->md_size;
    if (!out)
    {
        *outlen = nbytes;
        return 1;
    }

    if (*outlen < nbytes)
    {
        *outlen = nbytes;
        return retval;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    if ((k == NULL) || (order == NULL) || (h == NULL))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    if ((pub_key = EC_KEY_get0_public_key(ec_key)) == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

redo:
#ifdef TEST_SM2
    BN_hex2bn(&k, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
#else
    do
    {
        if (!BN_rand_range(k, order))
        {
            SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(k)) ;
#endif // TEST_SM2
    
    /*compute C1 = [k]G = (x1, y1)*/
    if (!EC_POINT_mul(group, C1, k, NULL, NULL, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("C1: [%s]\n", EC_POINT_point2hex(group, C1, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute S*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, h, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    /*check S is at infinity*/
    if (EC_POINT_is_at_infinity(group, point))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    /*now, compute [k]P = (x2, y2)*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, k, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("[k]P: [%s]\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute t = KDF_GMT003_2012(x2, y2)*/
    nbytes = deep * 2 + 1;
    if (buf == NULL)
        buf = OPENSSL_malloc(nbytes + 10);
    if (buf == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    nbytes = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, nbytes + 10, ctx);
    if (!nbytes)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    if (ckey == NULL)
        ckey = OPENSSL_malloc(inlen + 10);
    if (ckey == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, inlen, (const unsigned char *)(buf + 1), nbytes - 1, NULL, 0, md))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*Test KDF Key ALL Bits Is Zero*/
    chktag = 1;
    for (loop = 0; loop < inlen; loop++)
        if (ckey[loop] & 0xFF)
        {
            chktag = 0;
            break;
        }
    if (chktag)
        goto redo;

#ifdef TEST_SM2
    printf("t:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*compute C2: M xor t*/
    for (loop = 0; loop < inlen; loop++)
    {
        ckey[loop] ^= in[loop];
    }
#ifdef TEST_SM2
    printf("C2:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*compute Digest of x2 + M + y2*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, in, inlen);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
#ifdef TEST_SM2
    printf("C3:[");
    for (loop = 0; loop < md->md_size; loop++)
        printf("%02X", C3[loop]);
    printf("]\n");
#endif // TEST_SM2
    
    /*Now output result*/
    nbytes = 0;
    /*output C1*/
    nbytes = EC_POINT_point2oct(group, C1, POINT_CONVERSION_UNCOMPRESSED, out, *outlen, ctx);
    
    /*second: output C3*/
    memcpy(out + nbytes, C3, md->md_size);
    nbytes += md->md_size;
    
    /*output C2*/
    memcpy(out + nbytes, ckey, inlen);
    nbytes += inlen;
    
    /*output: outlen*/
    *outlen = nbytes;
    retval = 1;

err:
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);

    return retval;
}

/*SM2 Private Decrypt core function, in format is: C1 + C3 + C2*/
int __sm2_decrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    const BIGNUM *k = NULL;
    BIGNUM *h = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    size_t loop, deep, nbytes, from;
    unsigned char *buf = NULL, *ckey = NULL, C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;

    if (!outlen)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        return retval;
    }
    
    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    
    /*compute outlen, it must be conside to compressed point values*/
    from = in[0] & 0xFE; /*exclude y_bit*/
    if ((from != POINT_CONVERSION_COMPRESSED) && (from != POINT_CONVERSION_UNCOMPRESSED) && (from != POINT_CONVERSION_HYBRID))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_ARGUMENT);
        goto err;
    }
    
    /*compute temporary public key octet bytes*/
    if (from == POINT_CONVERSION_COMPRESSED)
        nbytes = deep + 1;
    else
        nbytes = 2 * deep + 1;

    /*compute plain text length*/
    loop = inlen - nbytes - md->md_size;

    if (!out)
    {
        *outlen = loop;
        return 1;
    }

    if (*outlen < loop)
    {
        *outlen = loop;
        return retval;
    }
    
    if ((ctx = BN_CTX_new()) == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    /*BN_CTX_start(ctx);*/
    h = BN_new();
    if (h == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if ((k = EC_KEY_get0_private_key(ec_key)) == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_BN_LIB);
        goto err;    
    }
    
    /*GET C1*/
    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    if (!EC_POINT_oct2point(group, C1, in, nbytes, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    /*DETECT C1 is on this curve*/
    /*this is not need, because function EC_POINT_oct2point was do it*/
    if (!EC_POINT_is_on_curve(group, C1, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_ARGUMENT);
        goto err;
    }
    
    /*DETECT [h]C1 is at infinity*/
    if (!EC_POINT_mul(group, point, NULL, C1, h, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    if (EC_POINT_is_at_infinity(group, point))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    /*COMPUTE [d]C1 into point*/
    if (!EC_POINT_mul(group, point, NULL, C1, k, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    /*OK, Now Compute t*/
    from = deep * 2 + 1;
    buf = OPENSSL_malloc(from + 10);
    if (buf == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    from = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, from + 10, ctx);
    if (!from)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }
    
    ckey = OPENSSL_malloc(loop + 10);
    if (ckey == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, loop, (const unsigned char *)(buf + 1), from - 1, NULL, 0, md))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*GET PLAIN TEXT, cipher text format is: C1 + C3 + C2*/
    for (from = 0; from < loop; from++)
    {
        ckey[from] ^= in[nbytes + md->md_size + from];
    }
    
    /*COMPUTE DIGEST*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, ckey, loop);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
    
    /*cipher text format is: C1 + C3 + C2*/
    if (memcmp(C3, in + nbytes, md->md_size))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EVP_LIB);
        goto err;
    }
    
    /*OK, SM2 Decrypt Successed*/
    memcpy(out, ckey, loop);
    *outlen = loop;
    
    retval = 1;
err:
    if (h) BN_free(h);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) 
    {
        /*BN_CTX_end(ctx);*/
        BN_CTX_free(ctx);
    }    

    return retval;
}

#ifdef SM2DH_TEST
#define SM2DH_Kap_Func(a)    SM2DH_Kap_Func_##a
#else
#define SM2DH_Kap_Func(a)    a
#endif //SM2DH_TEST

/*SM2DH: Like ECDH, According to ECDH interface*/
/*SM2DH ex_data index detector*/
int SM2DH_Kap_Func(SM2DH_get_ex_data_index)(void)
{
    static volatile int idx = -1;
    if (idx < 0) {
        CRYPTO_w_lock(CRYPTO_LOCK_ECDH);
        if (idx < 0) {
            idx = ECDH_get_ex_new_index(0, "SM2DHKAP", NULL, NULL, NULL);
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_ECDH);
    }
    return idx;
}

/*SM2DH ex_data apis*/
int SM2DH_Kap_Func(SM2DH_set_ex_data)(EC_KEY *ecKey, void *datas)
{
    return ECDH_set_ex_data(ecKey, SM2DH_Kap_Func(SM2DH_get_ex_data_index)(), datas);
}

void *SM2DH_Kap_Func(SM2DH_get_ex_data)(EC_KEY *ecKey)
{
    return ECDH_get_ex_data(ecKey, SM2DH_Kap_Func(SM2DH_get_ex_data_index)());
}

/*SM2DH: part 1 -- init*/
int SM2DH_Kap_Func(SM2DH_prepare)(EC_KEY *ecKey, int server, unsigned char *R, size_t *R_len)
{
    SM2DH_DATA *sm2Exdata = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *ecdhe_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ret = -1;

    while (!(sm2Exdata = (SM2DH_DATA *)OPENSSL_malloc(sizeof(SM2DH_DATA))))
        ;
    memset(sm2Exdata, 0, sizeof(SM2DH_DATA));
    sm2Exdata->server = server;

    pkey = EVP_PKEY_new();
    if (!pkey)
    {
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, ecKey))
    {
        /*assign EC_KEY to PKEY error*/
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx)
    {
        /*Create EVP_PKEY_CTX error*/
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) != 1)
    {
        /*keygen init error*/
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, EC_GROUP_get_curve_name(EC_KEY_get0_group(ecKey))) <= 0)
    {
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &ecdhe_key) != 1)
    {
        /*keygen error*/
        SM2err(SM2_F_SM2_PREPARE, ERR_R_EVP_LIB);
        goto err;
    }

    sm2Exdata->r_len = BN_bn2bin(EC_KEY_get0_private_key(ecdhe_key->pkey.ec), sm2Exdata->r);
    if (R)
    {
        size_t pub_len = EC_POINT_point2oct(EC_KEY_get0_group(ecdhe_key->pkey.ec), EC_KEY_get0_public_key(ecdhe_key->pkey.ec), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (*R_len < pub_len)
        {
            SM2err(SM2_F_SM2_PREPARE, ERR_R_EC_LIB);
            goto err;
        }

        pub_len = EC_POINT_point2oct(EC_KEY_get0_group(ecdhe_key->pkey.ec), EC_KEY_get0_public_key(ecdhe_key->pkey.ec), POINT_CONVERSION_UNCOMPRESSED, sm2Exdata->Rs, pub_len, NULL);
        if (!pub_len)
        {
            SM2err(SM2_F_SM2_PREPARE, ERR_R_EC_LIB);
            goto err;
        }
        sm2Exdata->Rs_len = (int)pub_len;
        *R_len = pub_len;
        memcpy(R, sm2Exdata->Rs, pub_len);
    }
    /*OK, Output EC private key And Public Key*/
    if (!SM2DH_Kap_Func(SM2DH_set_ex_data)(ecKey, (void *)(sm2Exdata)))
        goto err;

    ret = 1;

err:
    if (ecdhe_key) EVP_PKEY_free(ecdhe_key);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);

    return ret;
}

/*detail: 1, Need define a struct to storage some informations, like: client_or_server_flag, ECPKPARAMETERS, EC_POINT*/
int SM2DH_Kap_Func(SM2DH_compute_key)(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *eckey, void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen))
{
    SM2DH_DATA *sm2dhdata = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *Rs = NULL, *Rp = NULL; /*Rs: pubkey self*/
    EC_POINT *UorV = NULL;
    BIGNUM *Xs = NULL, *Xp = NULL, *r = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(eckey);
    if (priv_key == NULL)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    /*First: Detect Self And Peer Key Agreement Data ready, And others*/
    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);
    if ((sm2dhdata == NULL) || !sm2dhdata->r_len || !sm2dhdata->Rp_len)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if (!sm2dhdata->r_len || !sm2dhdata->Rp_len)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    r = BN_bin2bn((const unsigned char *)sm2dhdata->r, sm2dhdata->r_len, NULL);
    group = EC_KEY_get0_group(eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    Rs = EC_POINT_new(group);
    Rp = EC_POINT_new(group);
    UorV = EC_POINT_new(group);

    if (!Rs || !Rp || !UorV)
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point(group, Rs, sm2dhdata->Rs, (size_t)sm2dhdata->Rs_len, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_oct2point(group, Rp, sm2dhdata->Rp, (size_t)sm2dhdata->Rp_len, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("X%d:[%s]\n", (sm2dhdata->server ? 2 : 1), BN_bn2hex(Xs));
#endif

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("x%d:[%s]\n", (sm2dhdata->server ? 1 : 2), BN_bn2hex(Xp));
#endif

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("t%c:[%s]\n", (sm2dhdata->server ? 'B' : 'A'), BN_bn2hex(t));
#endif

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("[x%d]R%c:[%s]\n", (sm2dhdata->server ? 1 : 2), (sm2dhdata->server ? 'a' : 'b'), EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, pub_key, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("P%c + [x%d]R%c:[%s]\n", (sm2dhdata->server ? 'a' : 'b'), (sm2dhdata->server ? 1 : 2), (sm2dhdata->server ? 'a' : 'b'), EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("%c = [h * t%C](P%c + [x%d]R%c):[%s]\n",
        (sm2dhdata->server ? 'V' : 'U'),
        (sm2dhdata->server ? 'B' : 'A'),
        (sm2dhdata->server ? 'a' : 'b'),
        (sm2dhdata->server ? 1 : 2),
        (sm2dhdata->server ? 'a' : 'b'),
        EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx)
        );
#endif

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!sm2dhdata->server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(eckey, EVP_sm3(), (const char *)sm2dhdata->self_id, sm2dhdata->selfid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                printf("Za:[");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif
            idx += len;
        }

        /*Caculate Peer Z*/
        {
            EC_KEY *tmp_key = EC_KEY_new();

            if (!tmp_key)
            {
                SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!EC_KEY_set_group(tmp_key, group))
            {
                SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
                EC_KEY_free(tmp_key);
                goto err;
            }
            if (!EC_KEY_set_public_key(tmp_key, pub_key))
            {
                SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
                EC_KEY_free(tmp_key);
                goto err;
            }

            len = buflen - idx;

            /*SIDE B or SIDE A*/
            if (!ECDSA_sm2_get_Z(tmp_key, EVP_sm3(), (const char *)sm2dhdata->peer_id, sm2dhdata->peerid_len, (unsigned char *)(buf + idx), &len))
            {
                EC_KEY_free(tmp_key);
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                if (sm2dhdata->server)
                    printf("Za:[");
                else
                    printf("Zb: [");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif

            idx += len;
            EC_KEY_free(tmp_key);
        }

        if (sm2dhdata->server)
        {
            /*SIDE B*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(eckey, EVP_sm3(), (const char *)sm2dhdata->self_id, sm2dhdata->selfid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                printf("Zb:[");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif
            idx += len;
        }

        len = outlen;
        if (!KDF_GMT003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, EVP_sm3()))
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    /*Seventh: caculate checksum (if need)*/
    if (sm2dhdata->checksum)
    {
        EVP_MD_CTX md_ctx;

        unsigned char h_Yuorv[64 + 1 + EVP_MAX_MD_SIZE];
        unsigned char *h_Xuorv = NULL;
        size_t elemet_len, idx, idy;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        len = elemet_len * 5 + 32 * 2;
        h_Xuorv = (unsigned char *)OPENSSL_malloc(len + 10);
        if (!h_Xuorv)
        {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memset(h_Xuorv, 0, len + 10);

        /*buf: 1Tag + Xuorv + Yuorv + Za + Zb*/
        idx = 0;
        memcpy(h_Xuorv + idx, buf + 1, elemet_len);
        idx += elemet_len;
        memcpy(h_Yuorv + 1, buf + 1 + elemet_len, elemet_len);
        idy = 1 + elemet_len;

        /*Za + Zb*/
        memcpy(h_Xuorv + idx, buf + 1 + elemet_len * 2, 64);
        idx += 64;

        if (sm2dhdata->server)
        {
            memcpy(h_Xuorv + idx, sm2dhdata->Rp + 1, sm2dhdata->Rp_len - 1);
            idx += (sm2dhdata->Rp_len - 1);
            memcpy(h_Xuorv + idx, sm2dhdata->Rs + 1, sm2dhdata->Rs_len - 1);
            idx += (sm2dhdata->Rs_len - 1);
        }
        else
        {
            memcpy(h_Xuorv + idx, sm2dhdata->Rs + 1, sm2dhdata->Rs_len - 1);
            idx += (sm2dhdata->Rs_len - 1);
            memcpy(h_Xuorv + idx, sm2dhdata->Rp + 1, sm2dhdata->Rp_len - 1);
            idx += (sm2dhdata->Rp_len - 1);
        }

        EVP_DigestInit(&md_ctx, EVP_sm3());
        EVP_DigestUpdate(&md_ctx, h_Xuorv, idx);
        EVP_DigestFinal(&md_ctx, h_Yuorv + idy, NULL);
        idy += 32;
        EVP_MD_CTX_cleanup(&md_ctx);

        if (sm2dhdata->server)
        {
            /*SIDE B*/
            h_Yuorv[0] = (unsigned char)0x02;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->s_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

            h_Yuorv[0] = (unsigned char)0x03;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->e_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);
        }
        else
        {
            /*SIDE A*/
            h_Yuorv[0] = (unsigned char)0x03;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->s_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

            h_Yuorv[0] = (unsigned char)0x02;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->e_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

        }

        OPENSSL_free(h_Xuorv);

        SM2DH_Kap_Func(SM2DH_set_ex_data)(eckey, sm2dhdata);

    }

    ret = outlen;

err:
    if (r) BN_free(r);
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (Rs) EC_POINT_free(Rs);
    if (Rp) EC_POINT_free(Rp);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

/*Get SM2DH ensure information*/
int SM2DH_Kap_Func(SM2DH_get_ensure_checksum)(void *out, EC_KEY *eckey)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    if (out)
    {
        memcpy(out, sm2dhdata->e_checksum, md->md_size);
    }

    return md->md_size;
}

int SM2DH_Kap_Func(SM2DH_get_send_checksum)(void *out, EC_KEY *eckey)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    if (out)
    {
        memcpy(out, sm2dhdata->s_checksum, md->md_size);
    }

    return md->md_size;
}

int SM2DH_Kap_Func(SM2DH_set_checksum)(EC_KEY *eckey, int checksum)
{
    SM2DH_DATA *sm2dhdata = NULL;

    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    sm2dhdata->checksum = (checksum ? 1 : 0);

    return SM2DH_Kap_Func(SM2DH_set_ex_data)(eckey, (void *)sm2dhdata);
}

int SM2DH_Kap_Func(SM2Kap_compute_key)(void *out, size_t outlen, int server,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!peer_pub_key || !self_eckey)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }
    
    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (!priv_key)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    if (!peer_ecdhe_key || !self_ecdhe_key)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (!Rs || !Rp || !r)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);

    if (!UorV)
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(self_eckey, md, self_uid, self_uid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }

            idx += len;
        }

        /*Caculate Peer Z*/
        len = buflen - idx;
        if (!ECDSA_sm2_get_Z(peer_pub_key, md, peer_uid, peer_uid_len, (unsigned char *)(buf + idx), &len))
        {
            goto err;
        }
        idx += len;

        if (server)
        {
            /*SIDE B*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(self_eckey, md, self_uid, self_uid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
            idx += len;
        }

        len = outlen;
        if (!KDF_GMT003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, md))
        {
            SM2err(SM2_F_KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    ret = outlen;

err:
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

ASN1_SEQUENCE(SM2ENC) = {
    ASN1_SIMPLE(SM2ENC, x, ASN1_INTEGER),
    ASN1_SIMPLE(SM2ENC, y, ASN1_INTEGER),
    ASN1_SIMPLE(SM2ENC, m, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2ENC, c, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM2ENC)

DECLARE_ASN1_FUNCTIONS_const(SM2ENC)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM2ENC, SM2ENC)
IMPLEMENT_ASN1_FUNCTIONS_const(SM2ENC)

/* SM2 Public Encrypt core function: return NULL failure */
SM2ENC *sm2_encrypt(const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    const EC_GROUP *group;
    BIGNUM *k = NULL, *order = NULL, *h = NULL, *x = NULL, *y = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *pub_key = NULL;
    size_t loop, deep, nbytes;
    unsigned char *buf = NULL, *ckey = NULL;
    unsigned char C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;
    /*point_conversion_form_t from;*/
    int chktag;
    SM2ENC *retval = NULL;
    int ok = 0;

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        return NULL;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    nbytes = 1 + deep * 2 /*C1*/ + inlen + md->md_size;

    if ((ctx = BN_CTX_new()) == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if ((k == NULL) || (order == NULL) || (h == NULL) || (x == NULL) || (y == NULL))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if ((pub_key = EC_KEY_get0_public_key(ec_key)) == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

redo:
#ifdef TEST_SM2
    BN_hex2bn(&k, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
#else
    do
    {
        if (!BN_rand_range(k, order))
        {
            SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(k));
#endif // TEST_SM2

    /*compute C1 = [k]G = (x1, y1)*/
    if (!EC_POINT_mul(group, C1, k, NULL, NULL, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("C1: [%s]\n", EC_POINT_point2hex(group, C1, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute S*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, h, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*check S is at infinity*/
    if (EC_POINT_is_at_infinity(group, point))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*now, compute [k]P = (x2, y2)*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, k, ctx))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("[k]P: [%s]\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute t = KDF_GMT003_2012(x2, y2)*/
    nbytes = deep * 2 + 1;
    if (buf == NULL)
        buf = OPENSSL_malloc(nbytes + 10);
    if (buf == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    nbytes = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, nbytes + 10, ctx);
    if (!nbytes)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (ckey == NULL)
        ckey = OPENSSL_malloc(inlen + 10);
    if (ckey == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, inlen, (const unsigned char *)(buf + 1), nbytes - 1, NULL, 0, md))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*Test KDF Key ALL Bits Is Zero*/
    chktag = 1;
    for (loop = 0; loop < inlen; loop++)
        if (ckey[loop] & 0xFF)
        {
            chktag = 0;
            break;
        }
    if (chktag)
        goto redo;

#ifdef TEST_SM2
    printf("t:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*ALLOC Return Value*/
    retval = SM2ENC_new();
    if (!retval)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*compute C2: M xor t*/
    for (loop = 0; loop < inlen; loop++)
    {
        ckey[loop] ^= in[loop];
    }
#ifdef TEST_SM2
    printf("C2:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    if (!ASN1_OCTET_STRING_set(retval->c, (const unsigned char *)ckey, inlen))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    /*compute Digest of x2 + M + y2*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, in, inlen);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
#ifdef TEST_SM2
    printf("C3:[");
    for (loop = 0; loop < md->md_size; loop++)
        printf("%02X", C3[loop]);
    printf("]\n");
#endif // TEST_SM2

    if (!ASN1_OCTET_STRING_set(retval->m, (const unsigned char *)C3, md->md_size))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    /*output C1*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)C1, x, y, ctx))
        {
            SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m((const EC_GROUP *)group, (const EC_POINT *)C1, x, y, ctx))
        {
            SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, retval->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, retval->y))
    {
        SM2err(SM2_F_SM2_PUB_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    ok = 1;

err:
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (!ok)
    {
        if (retval)
        {
            SM2ENC_free(retval);
            retval = NULL;
        }
    }

    return retval;
}

/* SM2 Private Decrypt core function: return ZERO failure */
int sm2_decrypt(unsigned char *out, size_t *outlen, const SM2ENC *in, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    const BIGNUM *k = NULL;
    BIGNUM *h = NULL, *x = NULL, *y = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    size_t deep, from;
    unsigned char *buf = NULL, *ckey = NULL, C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;

    if (!outlen)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    /*compute plain text length*/
    if (!out)
    {
        *outlen = in->c->length;
        return 1;
    }

    if (*outlen < (size_t)in->c->length)
    {
        *outlen = in->c->length;
        return retval;
    }

    /*verify digest*/
    if (md->md_size != in->m->length)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_DIGEST);
        return retval;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        return retval;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    if ((ctx = BN_CTX_new()) == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*BN_CTX_start(ctx);*/
    h = BN_new();
    if (h == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if ((k = EC_KEY_get0_private_key(ec_key)) == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_BN_LIB);
        goto err;
    }

    /*GET C1*/
    x = ASN1_INTEGER_to_BN(in->x, NULL);
    y = ASN1_INTEGER_to_BN(in->y, NULL);
    if (!x || !y)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_set_affine_coordinates_GFp(group, C1, x, y, ctx))
        {
            SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_set_affine_coordinates_GF2m(group, C1, x, y, ctx))
        {
            SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*DETECT C1 is on this curve*/
    /*this is not need, because function EC_POINT_oct2point was do it*/
    if (!EC_POINT_is_on_curve(group, C1, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, SM2_R_INVALID_ARGUMENT);
        goto err;
    }

    /*DETECT [h]C1 is at infinity*/
    if (!EC_POINT_mul(group, point, NULL, C1, h, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_POINT_is_at_infinity(group, point))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*COMPUTE [d]C1 into point*/
    if (!EC_POINT_mul(group, point, NULL, C1, k, ctx))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*OK, Now Compute t*/
    from = deep * 2 + 1;
    buf = OPENSSL_malloc(from + 10);
    if (buf == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    from = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, from + 10, ctx);
    if (!from)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    ckey = OPENSSL_malloc(in->c->length + 10);
    if (ckey == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, in->c->length, (const unsigned char *)(buf + 1), from - 1, NULL, 0, md))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EC_LIB);
        goto err;
    }

    /*GET PLAIN TEXT, cipher text format is: C1 + C3 + C2*/
    for (from = 0; from < (size_t)in->c->length; from++)
    {
        ckey[from] ^= in->c->data[from];
    }

    /*COMPUTE DIGEST*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, ckey, in->c->length);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);

    /*cipher text format is: C1 + C3 + C2*/
    if (memcmp(C3, in->m->data, in->m->length))
    {
        SM2err(SM2_F_SM2_PRIV_DECRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    /*OK, SM2 Decrypt Successed*/
    memcpy(out, ckey, in->c->length);
    *outlen = in->c->length;

    retval = 1;
err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (h) BN_free(h);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx)
    {
        /*BN_CTX_end(ctx);*/
        BN_CTX_free(ctx);
    }

    return retval;
}

/* Convert SM2 Cipher Structure to charactor string */
int i2c_sm2_enc(const SM2ENC *sm2enc, unsigned char **out)
{
    int retval = 0;
    unsigned char *ot;
    int outlen;

    if ((sm2enc->x->length > 0x20) || (sm2enc->y->length > 0x20))
    {
        SM2err(SM2_F_SM2_CIPHER2TEXT, SM2_R_INVALID_CURVE);
        goto err;
    }

    /* NOW OUTPUT THE SM2 ENC DATA FORMAT C1C3C2 */
    outlen = 1 + /*sm2enc->x->length + sm2enc->y->length*/ 0x20 + 0x20 + sm2enc->m->length + sm2enc->c->length;
    if (!out)
    {
        retval = outlen;
        goto err;
    }

    if (*out == NULL)
        *out = OPENSSL_malloc(outlen);
    if (*out == NULL)
    {
        SM2err(SM2_F_SM2_CIPHER2TEXT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ot = *out;
    *ot++ = 0x04;
    retval = 1;
    memset(ot, 0, 0x40);
    memcpy(ot + 0x20 - sm2enc->x->length, sm2enc->x->data, sm2enc->x->length);
    retval += /*sm2enc->x->length*/0x20;
    ot += /*sm2enc->x->length*/0x20;

    memcpy(ot + 0x20 - sm2enc->y->length, sm2enc->y->data, sm2enc->y->length);
    retval += /*sm2enc->y->length*/0x20;
    ot += /*sm2enc->y->length*/0x20;

    memcpy(ot, sm2enc->m->data, sm2enc->m->length);
    retval += sm2enc->m->length;
    ot += sm2enc->m->length;

    memcpy(ot, sm2enc->c->data, sm2enc->c->length);
    retval += sm2enc->c->length;

err:
    return retval;
}

/* Convert SM2 Cipher charactor string to Structure */
SM2ENC *c2i_sm2_enc(const unsigned char *in, size_t inlen, int md_size)
{
    /* IN FORMART MUST PC + X + Y + M + C, C1C3C2 */
    const unsigned char *p;
    SM2ENC *sm2enc = NULL;
    size_t len;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int ok = 0;

    /*DETECT input is correct*/
    len = 1 + 0x40 + md_size;
    if (inlen <= len)
    {
        /*invalid input parameters*/
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, SM2_R_INVALID_CIPHER_TEXT);
        return NULL;
    }

    sm2enc = SM2ENC_new();
    if (!sm2enc)
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* SET sm2enc->m */
    p = (const unsigned char *)(in + 1 + 0x40);
    if (!ASN1_OCTET_STRING_set(sm2enc->m, p, md_size))
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET sm2enc->c */
    p = (const unsigned char *)(in + len);
    len = inlen - len;

    if (!ASN1_OCTET_STRING_set(sm2enc->c, p, len))
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET sm2enc->x sm2enc->y */
    p = in;
    len = 0x41;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group)
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_EC_LIB);
        goto err;
    }

    point = EC_POINT_new((const EC_GROUP *)group);
    if (!point)
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point((const EC_GROUP *)group, point, p, len, NULL))
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_EC_LIB);
        goto err;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y)
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_EC_LIB);
        goto err;
    }

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, sm2enc->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, sm2enc->y))
    {
        SM2err(SM2_F_SM2_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }
    
    ok = 1;

err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    if (!ok)
    {
        if (sm2enc)
        {
            SM2ENC_free(sm2enc);
            sm2enc = NULL;
        }
    }

    return sm2enc;
}

/* Convert EC Cipher Structure to charactor string */
int i2c_ec_enc(const SM2ENC *ec_enc, int curve_name, unsigned char **out)
{
    int retval = 0;
    unsigned char *ot;
    int outlen;
    EC_GROUP *group = NULL;
    int deep;

    /*First: get group*/
    group = EC_GROUP_new_by_curve_name(curve_name);
    if (!group)
    {
        SM2err(SM2_F_EC_CIPHER2TEXT, SM2_R_EC_GROUP_NEW_BY_NAME_FAILURE);
        goto err;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    if ((ec_enc->x->length > deep) || (ec_enc->y->length > deep))
    {
        SM2err(SM2_F_EC_CIPHER2TEXT, SM2_R_INVALID_CURVE);
        goto err;
    }

    /* NOW OUTPUT THE EC ENC DATA FORMAT C1C3C2 */
    outlen = 1 + 2 * deep + ec_enc->m->length + ec_enc->c->length;
    if (!out)
    {
        retval = outlen;
        goto err;
    }

    if (*out == NULL)
        *out = OPENSSL_malloc(outlen);
    if (*out == NULL)
    {
        SM2err(SM2_F_EC_CIPHER2TEXT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ot = *out;
    *ot++ = 0x04;
    retval = 1;
    memset(ot, 0, 2 * deep);
    memcpy(ot + deep - ec_enc->x->length, ec_enc->x->data, ec_enc->x->length);
    retval += deep;
    ot += deep;

    memcpy(ot + deep - ec_enc->y->length, ec_enc->y->data, ec_enc->y->length);
    retval += deep;
    ot += deep;

    memcpy(ot, ec_enc->m->data, ec_enc->m->length);
    retval += ec_enc->m->length;
    ot += ec_enc->m->length;

    memcpy(ot, ec_enc->c->data, ec_enc->c->length);
    retval += ec_enc->c->length;

err:
    if (group) EC_GROUP_free(group);

    return retval;
}

/* Convert EC Cipher charactor string to Structure */
SM2ENC *c2i_ec_enc(const unsigned char *in, size_t inlen, int curve_name, int md_size)
{
    /* IN FORMART MUST PC + X + Y + M + C, C1C3C2 */
    const unsigned char *p;
    SM2ENC *ec_enc = NULL;
    size_t len;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int deep;
    int ok = 0;

    group = EC_GROUP_new_by_curve_name(curve_name);
    if (!group)
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_EC_LIB);
        goto err;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    /*DETECT input is correct*/
    len = 1 + 2 * deep + md_size;
    if (inlen <= len)
    {
        /*invalid input parameters*/
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, SM2_R_INVALID_CIPHER_TEXT);
        return NULL;
    }

    ec_enc = SM2ENC_new();
    if (!ec_enc)
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* SET ec_enc->m */
    p = (const unsigned char *)(in + len - md_size);
    if (!ASN1_OCTET_STRING_set(ec_enc->m, p, md_size))
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET ec_enc->c */
    p = (const unsigned char *)(in + len);
    len = inlen - len;

    if (!ASN1_OCTET_STRING_set(ec_enc->c, p, len))
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET ec_enc->x ec_enc->y */
    p = in;
    len = 1 + 2 * deep;

    point = EC_POINT_new((const EC_GROUP *)group);
    if (!point)
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point((const EC_GROUP *)group, point, p, len, NULL))
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_EC_LIB);
        goto err;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y)
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
        {
            SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
        {
            SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, ec_enc->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, ec_enc->y))
    {
        SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_ASN1_LIB);
        goto err;
    }

    ok = 1;

err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    if (!ok)
    {
        if (ec_enc)
        {
            SM2ENC_free(ec_enc);
            ec_enc = NULL;
        }
    }

    return ec_enc;
}

void hex2bin(const unsigned char *hex, int len, unsigned char *bin)
{
    unsigned char CC;
    int i;

    for (i = 0; i < len / 2; i++)
    {
        CC = hex[i * 2];
        if ((CC >= '0') && (CC <= '9'))
        {
            CC -= '0';
        }
        else if ((CC >= 'A') && (CC <= 'F'))
        {
            CC = CC - 'A' + 0x0A;
        }
        else if ((CC >= 'a') && (CC <= 'f'))
        {
            CC = CC - 'a' + 0x0A;
        }
        bin[i] = (CC << 4) & 0xF0;

        CC = hex[i * 2 + 1];
        if ((CC >= '0') && (CC <= '9'))
        {
            CC -= '0';
        }
        else if ((CC >= 'A') && (CC <= 'F'))
        {
            CC = CC - 'A' + 0x0A;
        }
        else if ((CC >= 'a') && (CC <= 'f'))
        {
            CC = CC - 'a' + 0x0A;
        }
        else
            CC = 0;
        bin[i] |= (CC & 0x0F);
    }
}

void bin2hex(const unsigned char *bin, int len, unsigned char *hex)
{
    unsigned char CC;
    int i;

    for (i = 0; i < len; i++)
    {
        CC = (unsigned char)((bin[i] >> 4) & 0x0F);
        hex[i * 2] = (unsigned char)((CC < 0x0A) ? ('0' + CC) : ('A' + CC - 0x0A));
        CC = (unsigned char)(bin[i] & 0x0F);
        hex[i * 2 + 1] = (unsigned char)((CC < 0x0A) ? ('0' + CC) : ('A' + CC - 0x0A));
    }
}



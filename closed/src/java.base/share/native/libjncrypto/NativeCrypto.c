/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2025 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

#if defined(_AIX)
#include <dlfcn.h>
#include <sys/ldr.h>
#define DLFCN_LDINFO_SIZE (sizeof(struct ld_info) + _XOPEN_PATH_MAX + _XOPEN_NAME_MAX)
#elif defined(__APPLE__) /* defined(_AIX) */
#include <dlfcn.h>
#include <mach-o/dyld.h>
#elif defined(__linux__) /* defined(__APPLE__) */
#include <dlfcn.h>
#include <link.h>
#elif defined(_WIN32) /* defined(__linux__) */
#include <windows.h>
#endif /* defined(_AIX) */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ecdh.h>
#include <openssl/pkcs12.h>

#include <ctype.h>
#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"

#define OPENSSL_VERSION_CODE(major, minor, fix, patch) \
        ((((jlong)(major)) << 28) | ((minor) << 20) | ((fix) << 12) | (patch))

#define OPENSSL_VERSION_1_0_0 OPENSSL_VERSION_CODE(1, 0, 0, 0)
#define OPENSSL_VERSION_1_1_0 OPENSSL_VERSION_CODE(1, 1, 0, 0)
#define OPENSSL_VERSION_1_1_1 OPENSSL_VERSION_CODE(1, 1, 1, 0)
#define OPENSSL_VERSION_2_0_0 OPENSSL_VERSION_CODE(2, 0, 0, 0)
/* Per new OpenSSL naming convention starting from OpenSSL 3, all major versions are ABI and API compatible. */
#define OPENSSL_VERSION_3_0_0 OPENSSL_VERSION_CODE(3, 0, 0, 0)
#define OPENSSL_VERSION_4_0_0 OPENSSL_VERSION_CODE(4, 0, 0, 0)

/* OpenSSL operation modes. */
#define OPENSSL_ENCRYPTION_MODE 1
#define OPENSSL_DECRYPTION_MODE 0
#define OPENSSL_SAME_MODE (-1)

/* needed for OpenSSL 1.0.2 Thread handling routines */
#define CRYPTO_LOCK 1

#if defined(WINDOWS)
# include <windows.h>
#else /* defined(WINDOWS) */
# include <pthread.h>
#endif /* defined(WINDOWS) */

/* Header for NativeCrypto loading methods. */
static void * find_crypto_symbol(void *handle, const char *symname);
static void * find_crypto_library(jboolean traceEnabled, const char *chomepath);
static void unload_crypto_library(void *handle);

/* Header for RSA algorithm using 1.0.2 OpenSSL. */
int OSSL102_RSA_set0_key(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_factors(RSA *, BIGNUM *, BIGNUM *);
int OSSL102_RSA_set0_crt_params(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);

/* Define literals from OpenSSL 1.1.x so that it compiles with OpenSSL 1.0.x. */
#ifndef EVP_CTRL_AEAD_GET_TAG
#define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#endif

#ifndef EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#endif

#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG
#endif

/* Whether loaded library is in FIPS mode. */
static jboolean OSSL_IS_FIPS;

/* Header for EC algorithm */
jboolean OSSL_ECGF2M;
int setECPublicCoordinates(EC_KEY *, BIGNUM *, BIGNUM *, int);
int setECPublicKey(EC_KEY *, BIGNUM *, BIGNUM *, int);

/* Type definitions of function pointers. */
typedef char * OSSL_error_string_n_t(unsigned long, char *, size_t);
typedef char * OSSL_error_string_t(unsigned long, char *);
typedef unsigned long OSSL_get_error_t();
typedef const EVP_MD* OSSL_sha_t();
typedef EVP_MD_CTX* OSSL_MD_CTX_new_t();
typedef int OSSL_DigestInit_ex_t(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
typedef int OSSL_MD_CTX_copy_ex_t(EVP_MD_CTX *, const EVP_MD_CTX *);
typedef int OSSL_DigestUpdate_t(EVP_MD_CTX *, const void *, size_t);
typedef int OSSL_DigestFinal_ex_t(EVP_MD_CTX *, unsigned char *, unsigned int *);
typedef int OSSL_MD_CTX_reset_t(EVP_MD_CTX *);
typedef int OSSL_MD_CTX_free_t(EVP_MD_CTX *);
typedef EVP_CIPHER_CTX* OSSL_CIPHER_CTX_new_t();
typedef void OSSL_CIPHER_CTX_free_t(EVP_CIPHER_CTX *);
typedef const EVP_CIPHER* OSSL_cipher_t();
typedef int OSSL_CipherInit_ex_t(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                              ENGINE *, const unsigned char *, const unsigned char *, int);
typedef int OSSL_CIPHER_CTX_set_padding_t(EVP_CIPHER_CTX *, int);
typedef int OSSL_CipherUpdate_t(EVP_CIPHER_CTX *, unsigned char *, int *,
                              const unsigned char *, int);
typedef int OSSL_CipherFinal_ex_t(EVP_CIPHER_CTX *, unsigned char *, int *);
typedef int OSSL_CIPHER_CTX_ctrl_t(EVP_CIPHER_CTX *, int, int, void *);
typedef int OSSL_DecryptInit_ex_t(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                             ENGINE *, const unsigned char *, const unsigned char *);
typedef int OSSL_DecryptUpdate_t(EVP_CIPHER_CTX *, unsigned char *, int *,
                             const unsigned char *, int);
typedef int OSSL_DecryptFinal_t(EVP_CIPHER_CTX *, unsigned char *, int *);

typedef RSA* OSSL_RSA_new_t();
typedef int OSSL_RSA_set0_key_t(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);
typedef int OSSL_RSA_set0_factors_t(RSA *, BIGNUM *, BIGNUM *);
typedef void OSSL_RSA_free_t (RSA *);
typedef int OSSL_RSA_public_decrypt_t(int, const unsigned char *, unsigned char *, RSA *, int);
typedef int OSSL_RSA_private_encrypt_t (int, const unsigned char *, unsigned char *, RSA *, int);

typedef BIGNUM *OSSL_BN_new_t();
typedef BIGNUM *OSSL_BN_bin2bn_t (const unsigned char *, int, BIGNUM *);
typedef void OSSL_BN_set_negative_t (BIGNUM *, int);
typedef void OSSL_BN_free_t (BIGNUM *);
typedef int OSSL_BN_bn2bin_t(const BIGNUM *, unsigned char *);
typedef int OSSL_BN_num_bits_t(const BIGNUM *);

typedef int OSSL_EC_KEY_generate_key_t(EC_KEY *);
typedef void OSSL_EC_KEY_free_t(EC_KEY *);
typedef int OSSL_ECDH_compute_key_t(void *, size_t, const EC_POINT *, EC_KEY *, void *(*KDF)(const void *, size_t, void *, size_t *));
typedef const EC_POINT* OSSL_EC_KEY_get0_public_key_t(const EC_KEY *);
typedef EC_KEY* OSSL_EC_KEY_new_t(void);
typedef int OSSL_EC_KEY_set_public_key_affine_coordinates_t(EC_KEY *, BIGNUM *, BIGNUM *);
typedef int OSSL_EC_KEY_set_private_key_t(EC_KEY *, const BIGNUM *);
typedef BN_CTX* OSSL_BN_CTX_new_t(void);
typedef EC_GROUP* OSSL_EC_GROUP_new_curve_GFp_t(const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef EC_GROUP* OSSL_EC_GROUP_new_curve_GF2m_t(const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef int OSSL_EC_KEY_set_group_t(EC_KEY *, const EC_GROUP *);
typedef EC_POINT* OSSL_EC_POINT_new_t(const EC_GROUP *);
typedef int OSSL_EC_POINT_set_affine_coordinates_GFp_t(const EC_GROUP *, EC_POINT *, const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef int OSSL_EC_POINT_set_affine_coordinates_GF2m_t(const EC_GROUP *, EC_POINT *, const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef int OSSL_EC_POINT_get_affine_coordinates_GFp_t(const EC_GROUP *, const EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *);
typedef int OSSL_EC_POINT_get_affine_coordinates_GF2m_t(const EC_GROUP *, const EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *);
typedef int OSSL_EC_GROUP_set_generator_t(EC_GROUP *, const EC_POINT *, const BIGNUM *, const BIGNUM *);
typedef const EC_GROUP* OSSL_EC_KEY_get0_group_t(const EC_KEY *);
typedef void OSSL_EC_POINT_free_t(EC_POINT *);
typedef void OSSL_EC_GROUP_free_t(EC_GROUP *);
typedef void OSSL_BN_CTX_free_t(BN_CTX *);
typedef int OSSL_EC_KEY_set_public_key_t(EC_KEY *, const EC_POINT *);
typedef int OSSL_EC_KEY_check_key_t(const EC_KEY *);
typedef int EC_set_public_key_t(EC_KEY *, BIGNUM *, BIGNUM *, int);
typedef const BIGNUM *OSSL_EC_KEY_get0_private_key_t(const EC_KEY *);

typedef ECDSA_SIG *OSSL_ECDSA_do_sign_t(const unsigned char *, int, EC_KEY *);
typedef int OSSL_ECDSA_do_verify_t(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
typedef ECDSA_SIG *OSSL_ECDSA_SIG_new_t(void);
typedef void OSSL_ECDSA_SIG_free_t(ECDSA_SIG *);
typedef const BIGNUM *OSSL_ECDSA_SIG_get0_r_t(const ECDSA_SIG *);
typedef const BIGNUM *OSSL_ECDSA_SIG_get0_s_t(const ECDSA_SIG *);
typedef int OSSL_ECDSA_SIG_set0_t(ECDSA_SIG *, BIGNUM *, BIGNUM *);

typedef EVP_PKEY_CTX *OSSL_EVP_PKEY_CTX_new_t(EVP_PKEY *, ENGINE *);
typedef EVP_PKEY_CTX *OSSL_EVP_PKEY_CTX_new_id_t(int, ENGINE *);
typedef int OSSL_EVP_PKEY_keygen_init_t(EVP_PKEY_CTX *);
typedef int OSSL_EVP_PKEY_keygen_t(EVP_PKEY_CTX *, EVP_PKEY **);
typedef void OSSL_EVP_PKEY_CTX_free_t(EVP_PKEY_CTX *);
typedef int OSSL_EVP_PKEY_get_raw_private_key_t(const EVP_PKEY *, unsigned char *, size_t *);
typedef int OSSL_EVP_PKEY_get_raw_public_key_t(const EVP_PKEY *, unsigned char *, size_t *);
typedef EVP_PKEY *OSSL_EVP_PKEY_new_raw_private_key_t(int, ENGINE *, const unsigned char *, size_t);
typedef EVP_PKEY *OSSL_EVP_PKEY_new_raw_public_key_t(int, ENGINE *, const unsigned char *, size_t);
typedef int OSSL_EVP_PKEY_derive_init_t(EVP_PKEY_CTX *);
typedef int OSSL_EVP_PKEY_derive_set_peer_t(EVP_PKEY_CTX *, EVP_PKEY *);
typedef int OSSL_EVP_PKEY_derive_t(EVP_PKEY_CTX *, unsigned char *, size_t *);
typedef void OSSL_EVP_PKEY_free_t(EVP_PKEY *);

typedef int OSSL_PKCS12_key_gen_t(const char *, int, unsigned char *, int, int, int, int, unsigned char *, const EVP_MD *);

typedef int OSSL_CRYPTO_num_locks_t();
typedef void OSSL_CRYPTO_THREADID_set_numeric_t(CRYPTO_THREADID *id, unsigned long val);
typedef void* OSSL_OPENSSL_malloc_t(size_t num);
typedef void* OSSL_OPENSSL_free_t(void* addr);
typedef int OSSL_CRYPTO_THREADID_set_callback_t(void (*threadid_func)(CRYPTO_THREADID *));
typedef void OSSL_CRYPTO_set_locking_callback_t(void (*func)(int mode, int type, const char *file, int line));

static int thread_setup();
#if defined(WINDOWS)
static void win32_locking_callback(int mode, int type, const char *file, int line);
#else /* defined(WINDOWS) */
static void pthreads_thread_id(CRYPTO_THREADID *tid);
static void pthreads_locking_callback(int mode, int type, const char *file, int line);
#endif /* defined(WINDOWS) */

/* Define pointers for OpenSSL functions to handle Errors. */
OSSL_error_string_n_t* OSSL_error_string_n;
OSSL_error_string_t* OSSL_error_string;
OSSL_get_error_t* OSSL_get_error;

/* Define pointers for OpenSSL 1.0.2 threading routines. */
static OSSL_CRYPTO_num_locks_t* OSSL_CRYPTO_num_locks = NULL;
static OSSL_CRYPTO_THREADID_set_numeric_t* OSSL_CRYPTO_THREADID_set_numeric = NULL;
static OSSL_OPENSSL_malloc_t* OSSL_OPENSSL_malloc = NULL;
static OSSL_OPENSSL_free_t* OSSL_OPENSSL_free = NULL;
static OSSL_CRYPTO_THREADID_set_callback_t* OSSL_CRYPTO_THREADID_set_callback = NULL;
static OSSL_CRYPTO_set_locking_callback_t* OSSL_CRYPTO_set_locking_callback = NULL;

/* Define pointers for OpenSSL functions to handle Message Digest algorithms. */
OSSL_sha_t* OSSL_md5;
OSSL_sha_t* OSSL_sha1;
OSSL_sha_t* OSSL_sha256;
OSSL_sha_t* OSSL_sha224;
OSSL_sha_t* OSSL_sha384;
OSSL_sha_t* OSSL_sha512;
OSSL_MD_CTX_new_t* OSSL_MD_CTX_new;
OSSL_DigestInit_ex_t* OSSL_DigestInit_ex;
OSSL_MD_CTX_copy_ex_t* OSSL_MD_CTX_copy_ex;
OSSL_DigestUpdate_t* OSSL_DigestUpdate;
OSSL_DigestFinal_ex_t* OSSL_DigestFinal_ex;
OSSL_MD_CTX_reset_t* OSSL_MD_CTX_reset;
OSSL_MD_CTX_free_t* OSSL_MD_CTX_free;

/* Define pointers for OpenSSL functions to handle CBC and GCM Cipher algorithms. */
OSSL_CIPHER_CTX_new_t* OSSL_CIPHER_CTX_new;
OSSL_CIPHER_CTX_free_t* OSSL_CIPHER_CTX_free;
OSSL_cipher_t* OSSL_aes_128_cbc;
OSSL_cipher_t* OSSL_aes_192_cbc;
OSSL_cipher_t* OSSL_aes_256_cbc;
OSSL_CipherInit_ex_t* OSSL_CipherInit_ex;
OSSL_CIPHER_CTX_set_padding_t* OSSL_CIPHER_CTX_set_padding;
OSSL_CipherUpdate_t* OSSL_CipherUpdate;
OSSL_CipherFinal_ex_t* OSSL_CipherFinal_ex;

/* Define pointers for OpenSSL functions to handle GCM algorithm. */
OSSL_cipher_t* OSSL_aes_128_gcm;
OSSL_cipher_t* OSSL_aes_192_gcm;
OSSL_cipher_t* OSSL_aes_256_gcm;
OSSL_CIPHER_CTX_ctrl_t* OSSL_CIPHER_CTX_ctrl;
OSSL_DecryptInit_ex_t* OSSL_DecryptInit_ex;
OSSL_DecryptUpdate_t* OSSL_DecryptUpdate;
OSSL_DecryptFinal_t* OSSL_DecryptFinal;

/* Define pointers for OpenSSL functions to handle RSA algorithm. */
OSSL_RSA_new_t* OSSL_RSA_new;
OSSL_RSA_set0_key_t* OSSL_RSA_set0_key;
OSSL_RSA_set0_factors_t* OSSL_RSA_set0_factors;
OSSL_RSA_set0_key_t* OSSL_RSA_set0_crt_params;
OSSL_RSA_free_t* OSSL_RSA_free;
OSSL_RSA_public_decrypt_t* OSSL_RSA_public_decrypt;
OSSL_RSA_private_encrypt_t* OSSL_RSA_private_encrypt;

/* Define pointers for OpenSSL BIGNUM structs. */
OSSL_BN_new_t *OSSL_BN_new;
OSSL_BN_bin2bn_t* OSSL_BN_bin2bn;
OSSL_BN_set_negative_t* OSSL_BN_set_negative;
OSSL_BN_free_t* OSSL_BN_free;
OSSL_BN_bn2bin_t *OSSL_BN_bn2bin;
OSSL_BN_num_bits_t *OSSL_BN_num_bits;

/* Define pointers for OpenSSL functions to handle ChaCha20 algorithm. */
OSSL_cipher_t* OSSL_chacha20;
OSSL_cipher_t* OSSL_chacha20_poly1305;

/* Define pointers for OpenSSL functions to handle EC algorithm. */
OSSL_EC_KEY_generate_key_t *OSSL_EC_KEY_generate_key;
OSSL_EC_KEY_free_t* OSSL_EC_KEY_free;
OSSL_ECDH_compute_key_t* OSSL_ECDH_compute_key;
OSSL_EC_KEY_get0_public_key_t* OSSL_EC_KEY_get0_public_key;
OSSL_EC_KEY_new_t* OSSL_EC_KEY_new;
OSSL_EC_KEY_set_public_key_affine_coordinates_t* OSSL_EC_KEY_set_public_key_affine_coordinates;
OSSL_EC_KEY_set_private_key_t* OSSL_EC_KEY_set_private_key;
OSSL_BN_CTX_new_t* OSSL_BN_CTX_new;
OSSL_EC_GROUP_new_curve_GFp_t* OSSL_EC_GROUP_new_curve_GFp;
OSSL_EC_GROUP_new_curve_GF2m_t* OSSL_EC_GROUP_new_curve_GF2m;
OSSL_EC_KEY_set_group_t* OSSL_EC_KEY_set_group;
OSSL_EC_POINT_new_t* OSSL_EC_POINT_new;
OSSL_EC_POINT_set_affine_coordinates_GFp_t* OSSL_EC_POINT_set_affine_coordinates_GFp;
OSSL_EC_POINT_set_affine_coordinates_GF2m_t* OSSL_EC_POINT_set_affine_coordinates_GF2m;
OSSL_EC_POINT_get_affine_coordinates_GFp_t *OSSL_EC_POINT_get_affine_coordinates_GFp;
OSSL_EC_POINT_get_affine_coordinates_GF2m_t *OSSL_EC_POINT_get_affine_coordinates_GF2m;
OSSL_EC_GROUP_set_generator_t* OSSL_EC_GROUP_set_generator;
OSSL_EC_KEY_get0_group_t* OSSL_EC_KEY_get0_group;
OSSL_EC_POINT_free_t* OSSL_EC_POINT_free;
OSSL_EC_GROUP_free_t* OSSL_EC_GROUP_free;
OSSL_BN_CTX_free_t* OSSL_BN_CTX_free;
OSSL_EC_KEY_set_public_key_t* OSSL_EC_KEY_set_public_key;
OSSL_EC_KEY_check_key_t* OSSL_EC_KEY_check_key;
EC_set_public_key_t* EC_set_public_key;
OSSL_EC_KEY_get0_private_key_t *OSSL_EC_KEY_get0_private_key;

/* Define pointers for OpenSSL functions to handle ECDSA algorithm. */
OSSL_ECDSA_do_sign_t *OSSL_ECDSA_do_sign;
OSSL_ECDSA_do_verify_t *OSSL_ECDSA_do_verify;
OSSL_ECDSA_SIG_new_t *OSSL_ECDSA_SIG_new;
OSSL_ECDSA_SIG_free_t *OSSL_ECDSA_SIG_free;
OSSL_ECDSA_SIG_get0_r_t *OSSL_ECDSA_SIG_get0_r;
OSSL_ECDSA_SIG_get0_s_t *OSSL_ECDSA_SIG_get0_s;
OSSL_ECDSA_SIG_set0_t *OSSL_ECDSA_SIG_set0;

/* Define pointers for OpenSSL functions to handle XDH algorithm. */
OSSL_EVP_PKEY_CTX_new_t *OSSL_EVP_PKEY_CTX_new;
OSSL_EVP_PKEY_CTX_new_id_t *OSSL_EVP_PKEY_CTX_new_id;
OSSL_EVP_PKEY_keygen_init_t *OSSL_EVP_PKEY_keygen_init;
OSSL_EVP_PKEY_keygen_t *OSSL_EVP_PKEY_keygen;
OSSL_EVP_PKEY_CTX_free_t *OSSL_EVP_PKEY_CTX_free;
OSSL_EVP_PKEY_get_raw_private_key_t *OSSL_EVP_PKEY_get_raw_private_key;
OSSL_EVP_PKEY_get_raw_public_key_t *OSSL_EVP_PKEY_get_raw_public_key;
OSSL_EVP_PKEY_new_raw_private_key_t *OSSL_EVP_PKEY_new_raw_private_key;
OSSL_EVP_PKEY_new_raw_public_key_t *OSSL_EVP_PKEY_new_raw_public_key;
OSSL_EVP_PKEY_derive_init_t *OSSL_EVP_PKEY_derive_init;
OSSL_EVP_PKEY_derive_set_peer_t *OSSL_EVP_PKEY_derive_set_peer;
OSSL_EVP_PKEY_derive_t *OSSL_EVP_PKEY_derive;
OSSL_EVP_PKEY_free_t *OSSL_EVP_PKEY_free;

/* Define pointers for OpenSSL functions to handle PBE algorithm. */
OSSL_PKCS12_key_gen_t* OSSL_PKCS12_key_gen;

/* Structure for OpenSSL Digest context. */
typedef struct OpenSSLMDContext {
    EVP_MD_CTX *ctx;
    const EVP_MD *digestAlg;
    EVP_MD_CTX *cachedInitializedDigestContext;
} OpenSSLMDContext;

/* Handle errors from OpenSSL calls. */
static void printErrors(void)
{
    unsigned long errCode = 0;

    fprintf(stderr, "An OpenSSL error occurred\n");
    while (0 != (errCode = (*OSSL_get_error)())) {
        char err_str[120];
        (*OSSL_error_string_n)(errCode, err_str, (sizeof(err_str) / sizeof(char)));
        fprintf(stderr, "%s\n", err_str);
    }
    fflush(stderr);
}

/*
 * We use a 8 digit map (ABBCCDDD) to represent the version of openssl.
 * A is the major version,
 * BB is the minor version,
 * CC is the fix,
 * DDD is the patch that could be present in any version.
 * For example, if an openssl version is in this scheme 1.2.3.d
 * where major is 1, minor is 2, fix is 3 and patch is d -> 4.
 * So the result would be 0x10203004, where A is 1, BB is 02, CC is 03, DDD is 004.
 */
static jlong extractVersionToJlong(const char *astring)
{
    long major = 0;
    long minor = 0;
    long fix = 0;
    long patch = 0;
    char patch_char = 0;
    if (sscanf(astring, "OpenSSL %ld.%ld.%ld%c", &major, &minor, &fix, &patch_char) < 3) {
        return -1;
    }
    if (isalpha(patch_char)) {
        patch = tolower(patch_char) - 'a' + 1;
    }
    return (jlong)OPENSSL_VERSION_CODE(major, minor, fix, patch);
}

static void *crypto_library = NULL;

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    isOpenSSLFIPS
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_isOpenSSLFIPS
  (JNIEnv *env, jclass clazz)
{
    return OSSL_IS_FIPS;
}

/* Unload the crypto library. */
static void
unload_crypto_library(void *crypto_library)
{
#if defined(_WIN32)
    FreeLibrary(crypto_library);
#else /* defined(_WIN32) */
    (void)dlclose(crypto_library);
#endif /* defined(_WIN32) */
}

/* Find the symbol in the crypto library (return NULL if not found). */
static void *
find_crypto_symbol(void *crypto_library, const char *symname)
{
#if defined(_WIN32)
    return GetProcAddress(crypto_library, symname);
#else /* defined(_WIN32) */
    return dlsym(crypto_library, symname);
#endif /* defined(_WIN32) */
}

static void
log_crypto_library_path(jboolean traceEnabled, void *crypto_library, const char *message)
{
    if (traceEnabled && (NULL != crypto_library)) {
#if defined(_AIX)
        int rc = 0;
        /* Initialize the buffer with maximum size for L_GETINFO. */
        char *buffer = (char *)malloc(DLFCN_LDINFO_SIZE);
        if (NULL == buffer) {
            return;
        }
        /* Get the list of all object files loaded by this process. */
        rc = loadquery(L_GETINFO, buffer, DLFCN_LDINFO_SIZE);

        /* Parse the list of all object files and print the OPENSSL library path. */
        if (0 == rc) {
            char *buf = buffer;
            for (;;) {
                struct ld_info *cur_info = (struct ld_info *)buf;
                const char *path = cur_info->ldinfo_filename;
                const char *member_name = path + strlen(cur_info->ldinfo_filename) + 1;
                if (('\0' != *member_name) && (NULL != strstr(path, "/libcrypto"))) {
                    fprintf(stdout, "%s: %s(%s)\n", message, path, member_name);
                    fflush(stdout);
                    break;
                }
                if (0 == cur_info->ldinfo_next) {
                    break;
                }
                buf += cur_info->ldinfo_next;
            }
        }
        free(buffer);
#elif defined(__APPLE__) /* defined(_AIX) */
        /* Since we know the image we want will always be near the end of the list, start there and go backwards. */
        uint32_t i = _dyld_image_count() - 1;
        for (; i >= 0; i--) {
            const char *image_name = _dyld_get_image_name(i);
            void *probe_handle = NULL;
            jboolean same_handle = JNI_FALSE;
            if (NULL == image_name) {
                continue;
            }

            /* Why dlopen doesn't affect _dyld stuff: if an image is already loaded, it returns the existing handle. */
            probe_handle = dlopen(image_name, RTLD_LAZY);
            if (NULL == probe_handle) {
                continue;
            }
            if (crypto_library == probe_handle) {
                same_handle = JNI_TRUE;
            }
            dlclose(probe_handle);

            if (same_handle) {
                fprintf(stdout, "OpenSSL was loaded from - %s\n", image_name);
                fflush(stdout);
                break;
            }
        }
#elif defined(_WIN32) /* defined(__APPLE__) */
        char path[MAX_PATH];
        DWORD written = GetModuleFileName(crypto_library, path, MAX_PATH);
        if (0 != written) {
            fprintf(stdout, "OpenSSL was loaded from - %s\n", path);
            fflush(stdout);
        }
#else /* defined(_WIN32) */
        struct link_map *map = NULL;
        int ret = dlinfo(crypto_library, RTLD_DI_LINKMAP, &map);
        if ((0 == ret) && (NULL != map)) {
            fprintf(stdout, "OpenSSL was loaded from - %s\n", map->l_name);
            fflush(stdout);
        }
#endif /* defined(_AIX) */
    }
}

/* Get the version for the crypto library. */
static jlong
get_crypto_library_version(jboolean traceEnabled, void *crypto_library, const char *message)
{
    typedef const char *OSSL_version_t(int);
    OSSL_version_t *OSSL_version = NULL;
    const char *openssl_version = NULL;
    jlong ossl_ver = 0;

    /*
     * Different symbols are used by OpenSSL with 1.0 and 1.1 and later.
     * The symbol 'OpenSSL_version' is used by OpenSSL 1.1 and later where as
     * the symbol "SSLeay_version" is used by OpenSSL 1.0.
     * Currently only openssl 1.0.x, 1.1.x and 3.x.x are supported.
     */
    OSSL_version = (OSSL_version_t*)find_crypto_symbol(crypto_library, "OpenSSL_version");

    if (NULL == OSSL_version) {
        OSSL_version = (OSSL_version_t*)find_crypto_symbol(crypto_library, "SSLeay_version");

        if (NULL == OSSL_version) {
            if (traceEnabled) {
                fprintf(stderr, "Error loading OpenSSL: Error finding the OpenSSL version symbol in the crypto library\n");
                fflush(stderr);
            }
            unload_crypto_library(crypto_library);
            crypto_library = NULL;
            return -1;
        } else {
            openssl_version = (*OSSL_version)(0); /* get OPENSSL_VERSION */
            /* Ensure the OpenSSL version is "OpenSSL 1.0.x" */
            ossl_ver = extractVersionToJlong(openssl_version);
            if (!((OPENSSL_VERSION_1_0_0 <= ossl_ver) && (ossl_ver < OPENSSL_VERSION_1_1_0))) {
                if (traceEnabled) {
                    fprintf(stderr, "Error loading OpenSSL: Incompatible OpenSSL version found: %s\n", openssl_version);
                    fflush(stderr);
                }
                unload_crypto_library(crypto_library);
                crypto_library = NULL;
                return -1;
            }
        }
    } else {
        openssl_version = (*OSSL_version)(0); /* get OPENSSL_VERSION */
        /* Ensure the OpenSSL version is "OpenSSL 1.1.x" or "OpenSSL 3.x.x". */
        ossl_ver = extractVersionToJlong(openssl_version);
        if (!(((OPENSSL_VERSION_1_1_0 <= ossl_ver) && (ossl_ver < OPENSSL_VERSION_2_0_0))
           || ((OPENSSL_VERSION_3_0_0 <= ossl_ver) && (ossl_ver < OPENSSL_VERSION_4_0_0)))
        ) {
            if (traceEnabled) {
                fprintf(stderr, "Error loading OpenSSL: Incompatible OpenSSL version found: %s\n", openssl_version);
                fflush(stderr);
            }
            unload_crypto_library(crypto_library);
            crypto_library = NULL;
            return -1;
        }
    }

    /* Check whether the loaded OpenSSL library is in FIPS mode. */
    if (ossl_ver >= OPENSSL_VERSION_3_0_0) {
        typedef int OSSL_fipsmode_t(OSSL_LIB_CTX *);
        OSSL_fipsmode_t *ossl_fipsmode = (OSSL_fipsmode_t *)find_crypto_symbol(crypto_library, "EVP_default_properties_is_fips_enabled");
        if ((NULL != ossl_fipsmode) && (1 == (*ossl_fipsmode)(NULL))) {
            OSSL_IS_FIPS = JNI_TRUE;
        } else {
            OSSL_IS_FIPS = JNI_FALSE;
        }
    } else {
        typedef int OSSL_fipsmode_t(void);
        OSSL_fipsmode_t *ossl_fipsmode = (OSSL_fipsmode_t *)find_crypto_symbol(crypto_library, "FIPS_mode");
        if ((NULL != ossl_fipsmode) && (1 == (*ossl_fipsmode)())) {
            OSSL_IS_FIPS = JNI_TRUE;
        } else {
            OSSL_IS_FIPS = JNI_FALSE;
        }
    }

    if (traceEnabled) {
        fprintf(stdout, "%s: %s\n", message, openssl_version);
        fflush(stdout);
    }

    return ossl_ver;
}

static void *
load_crypto_library(jboolean traceEnabled, const char *libName)
{
    void *result = NULL;
    if ((NULL != libName) && ('\0' != *libName)) {
#if defined(_AIX)
        int flags = RTLD_NOW;
        if (NULL != strrchr(libName, '(')) {
            flags |= RTLD_MEMBER;
        }
        result = dlopen(libName, flags);
#elif defined(_WIN32) /* defined(_AIX) */
        result = LoadLibrary(libName);
#else /* defined(_WIN32) */
        result = dlopen(libName, RTLD_NOW);
#endif /* defined(_AIX) */
    }
    return result;
}

/* Look for a crypto library in java.home or the system.
 * NULL is returned when an appropriate crypto library
 * cannot be found.
 */
static void *
find_crypto_library(jboolean traceEnabled, const char *chomepath)
{
    /* Library names for OpenSSL 1.1.1, 1.1.0 and symbolic links:
     * It is important to preserve the order!!!
     *
     * Since there is no indication of the version of a symlink,
     * they have to be loaded first, so as to compare with other
     * available options.
     * Note: On macOS 11 or later, loading the general symlink causes
     * a fatal warning and associated abort by default, so it is
     * omitted.
     *
     * The rest of the libraries are listed in descending order,
     * which allows us to do two things:
     * - Stop if a general symlink is loaded and we then find a
     *   specific version that is higher.
     * - Stop immediately if a specific version is loaded, as
     *   anything after that will be a lower version.
     */
    static const char * const libNames[] = {
#if defined(_AIX)
        "libcrypto.a(libcrypto64.so)",      /* general symlink library name from archive file */
        "libcrypto64.so",                   /* general symlink library name */
        "libcrypto.a(libcrypto.so)",        /* general symlink library name from archive file */
        "libcrypto.so",                     /* general symlink library name */
        "libcrypto.a(libcrypto64.so.3)",    /* 3.x library name from archive file */
        "libcrypto64.so.3",                 /* 3.x library name */
        "libcrypto.a(libcrypto.so.3)",      /* 3.x library name from archive file */
        "libcrypto.so.3",                   /* 3.x library name */
        "libcrypto.a(libcrypto64.so.1.1)",  /* 1.1.x library name from archive file */
        "libcrypto.so.1.1",                 /* 1.1.x library name */
        "libcrypto.a(libcrypto.so.1.0.0)",  /* 1.0.x library name from archive file */
        "libcrypto.so.1.0.0",               /* 1.0.x library name */
#elif defined(__APPLE__) /* defined(_AIX) */
        "libcrypto.3.dylib",                /* 3.x library name */
        "libcrypto.1.1.dylib",              /* 1.1.x library name */
        "libcrypto.1.0.0.dylib",            /* 1.0.x library name */
#elif defined(_WIN32) /* defined(__APPLE__) */
        "libcrypto-3-x64.dll",              /* 3.x library name */
        "libcrypto-1_1-x64.dll",            /* 1.1.x library name */
        "libeay32.dll",                     /* old library name */
#else /* defined(_WIN32) */
        "libcrypto.so",                     /* general symlink library name */
        "libcrypto.so.3",                   /* 3.x library name */
        "libcrypto.so.1.1",                 /* 1.1.x library name */
        "libcrypto.so.1.0.0",               /* 1.0.x library name */
        "libcrypto.so.10",                  /* old library name */
#endif /* defined(_AIX) */
    };

    const size_t numOfLibs = sizeof(libNames) / sizeof(libNames[0]);
#if defined(_AIX)
    const size_t num_of_generic = 4;
#elif defined(__linux__) /* defined(_AIX) */
    const size_t num_of_generic = 1;
#else /* defined(__linux__) */
    const size_t num_of_generic = 0;
#endif /* defined(_AIX) */

    void *result = NULL;
    void *prevResult = NULL;
    size_t i = 0;
    long tempVersion = 0;
    long previousVersion = 0;

    /* If JAVA_HOME is not null or empty and no library has been loaded yet, try there. */
    if ((NULL != chomepath) && ('\0' != *chomepath) && (NULL == crypto_library)) {
#if defined(_WIN32)
        static const char pathSuffix[] = "\\bin\\";
#else /* defined(_WIN32) */
        static const char pathSuffix[] = "/lib/";
#endif /* defined(_WIN32) */

        size_t path_len = strlen(chomepath) + sizeof(pathSuffix) - 1;
        char *libPath = malloc(path_len + 1);

        if (NULL == libPath) {
            if (traceEnabled) {
                fprintf(stderr, "\tFailed to allocate memory for path.\n");
            }
            return NULL;
        }
        strcpy(libPath, chomepath);

        /* Append the proper directory using a slash or backslash, depending on the operating system. */
        strcat(libPath, pathSuffix);

        if (traceEnabled) {
            fprintf(stdout, "Attempting to load library bundled with JDK from: %s\n", libPath);
        }

        for (i = 0; i < numOfLibs; i++) {
            size_t file_len = strlen(libNames[i]);
            /* Allocate memory for the new file name with the path. */
            char *libNameWithPath = (char *)malloc(path_len + file_len + 1);

            if (NULL == libNameWithPath) {
                if (traceEnabled) {
                    fprintf(stderr, "\tFailed to allocate memory for file name with path.\n");
                }
                continue;
            }

            strcpy(libNameWithPath, libPath);
            strcat(libNameWithPath, libNames[i]);

            /* Load OpenSSL Crypto library bundled with JDK. */
            if (traceEnabled) {
                fprintf(stdout, "\tAttempting to load: %s\n", libNames[i]);
            }
            result = load_crypto_library(traceEnabled, libNameWithPath);

            free(libNameWithPath);

            if (NULL == result) {
                continue;
            }

            /* Identify and load the latest version from the potential libraries.
             * This logic depends upon the order in which libnames are defined.
             * Libraries are listed in descending order w.r.t version.
             * Since only one library is bundled with the JDK, once any library is
             * loaded, this is the only available and we can stop.
             */
            tempVersion = get_crypto_library_version(traceEnabled, result, "\t\tLoaded OpenSSL version");
            if (tempVersion > 0) {
                free(libPath);
                return result;
            }
        }
        free(libPath);
    }

    /* The attempt to load from property and OpenSSL bundled with JDK failed.
     * Try loading the libraries in the order set out above, and retain the latest library.
     */
    for (i = 0; i < numOfLibs; i++) {
        if (traceEnabled) {
            fprintf(stdout, "Attempting to load libname from OS: %s\n", libNames[i]);
        }
        result = load_crypto_library(traceEnabled, libNames[i]);

        if (NULL == result) {
            continue;
        }

        /* Identify and load the latest version from the available libraries.
         * This logic depends upon the order in which libnames are defined.
         * It only loads the libraries which can possibly be the latest versions.
         */
        log_crypto_library_path(traceEnabled, result, "\tLibrary to be potentially used was loaded from");
        tempVersion = get_crypto_library_version(traceEnabled, result, "\tLoaded OpenSSL version");

        if (tempVersion <= 0) {
            continue;
        }

        if (tempVersion > previousVersion) {
            if (0 != previousVersion) {
                unload_crypto_library(prevResult);
            }
            previousVersion = tempVersion;
            prevResult = result;
        } else {
            unload_crypto_library(result);
        }

        /* If library checked is not a generic one, there is no need to check further. */
        if (i >= num_of_generic) {
            break;
        }
    }

    /* If we reach here, it means that none of the non-generic libraries
     * where found. However, a generic one might have been found in the
     * process and, if so, it will be in the prevResult variable.
     */
    return prevResult;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    loadCrypto
 * Signature: (ZLjava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_loadCrypto
  (JNIEnv * env, jobject jobj, jboolean traceEnabled, jstring jlibname, jstring jhomepath)
{
    const char *chomepath = "";
    jlong ossl_ver = 0;

    if (NULL != jlibname) {
        const char *clibname = (*env)->GetStringUTFChars(env, jlibname, NULL);
        if (NULL == clibname) {
            if (traceEnabled) {
                fprintf(stderr, "Failed to get jdk.native.openssl.lib value.\n");
                fflush(stderr);
            }
            return -1;
        }
        if ('\0' == clibname[0]) {
            if (traceEnabled) {
                fprintf(stderr, "The jdk.native.openssl.lib property is not set.\n");
                fflush(stderr);
            }
        } else {
            crypto_library = load_crypto_library(traceEnabled, clibname);
            if (NULL == crypto_library) {
                if (traceEnabled) {
                    fprintf(stderr, "OpenSSL library specified in jdk.openssl.lib couldn't be loaded.\n");
                    fflush(stderr);
                }
                (*env)->ReleaseStringUTFChars(env, jlibname, clibname);
                return -1;
            }
        }
        (*env)->ReleaseStringUTFChars(env, jlibname, clibname);
    }

    if (NULL != jhomepath) {
        chomepath = (*env)->GetStringUTFChars(env, jhomepath, NULL);
        if (NULL == chomepath) {
            if (traceEnabled) {
                fprintf(stderr, "Failed to get java.home value.\n");
                fflush(stderr);
            }
            return -1;
        }
    }

    /* If the jdk.native.openssl.lib property was not set, attempt
     * to find an OpenSSL library from java.home or OS Library path.
     */
    if (NULL == crypto_library) {
        crypto_library = find_crypto_library(traceEnabled, chomepath);
    }

    if (NULL != jhomepath) {
        (*env)->ReleaseStringUTFChars(env, jhomepath, chomepath);
    }

    /* If an OpenSSL library was not loaded from any of the potential
     * sources, fail loading native crypto.
     */
    if (NULL == crypto_library) {
        if (traceEnabled) {
            fprintf(stderr, "FAILED TO LOAD OPENSSL CRYPTO LIBRARY\n");
            fflush(stderr);
        }
        return -1;
    }

    log_crypto_library_path(traceEnabled, crypto_library, "OpenSSL to be used was loaded from");
    ossl_ver = get_crypto_library_version(traceEnabled, crypto_library, "Version of OpenSSL library that is used");

    /* Load the function symbols for OpenSSL errors. */
    OSSL_error_string_n = (OSSL_error_string_n_t*)find_crypto_symbol(crypto_library, "ERR_error_string_n");
    OSSL_error_string = (OSSL_error_string_t*)find_crypto_symbol(crypto_library, "ERR_error_string");
    OSSL_get_error = (OSSL_get_error_t*)find_crypto_symbol(crypto_library, "ERR_get_error");

    /* Load Threading routines for OpenSSL 1.0.2. */
    if (ossl_ver < OPENSSL_VERSION_1_1_0) {
        OSSL_CRYPTO_num_locks = (OSSL_CRYPTO_num_locks_t*)find_crypto_symbol(crypto_library, "CRYPTO_num_locks");
        OSSL_CRYPTO_THREADID_set_numeric = (OSSL_CRYPTO_THREADID_set_numeric_t*)find_crypto_symbol(crypto_library, "CRYPTO_THREADID_set_numeric");
        OSSL_OPENSSL_malloc = (OSSL_OPENSSL_malloc_t*)find_crypto_symbol(crypto_library, "CRYPTO_malloc");
        OSSL_OPENSSL_free = (OSSL_OPENSSL_free_t*)find_crypto_symbol(crypto_library, "CRYPTO_free");
        OSSL_CRYPTO_THREADID_set_callback = (OSSL_CRYPTO_THREADID_set_callback_t*)find_crypto_symbol(crypto_library, "CRYPTO_THREADID_set_callback");
        OSSL_CRYPTO_set_locking_callback = (OSSL_CRYPTO_set_locking_callback_t*)find_crypto_symbol(crypto_library, "CRYPTO_set_locking_callback");
    }

    /* Load the function symbols for OpenSSL Message Digest algorithms. */
    OSSL_md5 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_md5");
    OSSL_sha1 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_sha1");
    OSSL_sha256 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_sha256");
    OSSL_sha224 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_sha224");
    OSSL_sha384 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_sha384");
    OSSL_sha512 = (OSSL_sha_t*)find_crypto_symbol(crypto_library, "EVP_sha512");

    if (ossl_ver >= OPENSSL_VERSION_1_1_0) {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_new");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_reset");
        OSSL_MD_CTX_free = (OSSL_MD_CTX_free_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_free");
    } else {
        OSSL_MD_CTX_new = (OSSL_MD_CTX_new_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_create");
        OSSL_MD_CTX_reset = (OSSL_MD_CTX_reset_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_cleanup");
        OSSL_MD_CTX_free = (OSSL_MD_CTX_free_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_destroy");
    }

    OSSL_DigestInit_ex = (OSSL_DigestInit_ex_t*)find_crypto_symbol(crypto_library, "EVP_DigestInit_ex");
    OSSL_MD_CTX_copy_ex = (OSSL_MD_CTX_copy_ex_t*)find_crypto_symbol(crypto_library, "EVP_MD_CTX_copy_ex");
    OSSL_DigestUpdate = (OSSL_DigestUpdate_t*)find_crypto_symbol(crypto_library, "EVP_DigestUpdate");
    OSSL_DigestFinal_ex = (OSSL_DigestFinal_ex_t*)find_crypto_symbol(crypto_library, "EVP_DigestFinal_ex");

    /* Load the function symbols for OpenSSL CBC and GCM Cipher algorithms. */
    OSSL_CIPHER_CTX_new = (OSSL_CIPHER_CTX_new_t*)find_crypto_symbol(crypto_library, "EVP_CIPHER_CTX_new");
    OSSL_CIPHER_CTX_free = (OSSL_CIPHER_CTX_free_t*)find_crypto_symbol(crypto_library, "EVP_CIPHER_CTX_free");
    OSSL_aes_128_cbc = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_128_cbc");
    OSSL_aes_192_cbc = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_192_cbc");
    OSSL_aes_256_cbc = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_256_cbc");
    OSSL_CipherInit_ex = (OSSL_CipherInit_ex_t*)find_crypto_symbol(crypto_library, "EVP_CipherInit_ex");
    OSSL_CIPHER_CTX_set_padding = (OSSL_CIPHER_CTX_set_padding_t*)find_crypto_symbol(crypto_library, "EVP_CIPHER_CTX_set_padding");
    OSSL_CipherUpdate = (OSSL_CipherUpdate_t*)find_crypto_symbol(crypto_library, "EVP_CipherUpdate");
    OSSL_CipherFinal_ex = (OSSL_CipherFinal_ex_t*)find_crypto_symbol(crypto_library, "EVP_CipherFinal_ex");
    OSSL_aes_128_gcm = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_128_gcm");
    OSSL_aes_192_gcm = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_192_gcm");
    OSSL_aes_256_gcm = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_aes_256_gcm");
    OSSL_CIPHER_CTX_ctrl = (OSSL_CIPHER_CTX_ctrl_t*)find_crypto_symbol(crypto_library, "EVP_CIPHER_CTX_ctrl");
    OSSL_DecryptInit_ex = (OSSL_DecryptInit_ex_t*)find_crypto_symbol(crypto_library, "EVP_DecryptInit_ex");
    OSSL_DecryptUpdate = (OSSL_DecryptUpdate_t*)find_crypto_symbol(crypto_library, "EVP_DecryptUpdate");
    OSSL_DecryptFinal = (OSSL_DecryptFinal_t*)find_crypto_symbol(crypto_library, "EVP_DecryptFinal");

    /* Load the functions symbols for OpenSSL ChaCha20 algorithms. (Need OpenSSL 1.1.x or above) */
    if (ossl_ver >= OPENSSL_VERSION_1_1_0) {
        OSSL_chacha20 = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_chacha20");
        OSSL_chacha20_poly1305 = (OSSL_cipher_t*)find_crypto_symbol(crypto_library, "EVP_chacha20_poly1305");
    } else {
        OSSL_chacha20 = NULL;
        OSSL_chacha20_poly1305 = NULL;
    }

    /* Load the functions symbols for OpenSSL RSA algorithm. */
    OSSL_RSA_new = (OSSL_RSA_new_t*)find_crypto_symbol(crypto_library, "RSA_new");

    if (ossl_ver >= OPENSSL_VERSION_1_1_0) {
        OSSL_RSA_set0_key = (OSSL_RSA_set0_key_t*)find_crypto_symbol(crypto_library, "RSA_set0_key");
        OSSL_RSA_set0_factors = (OSSL_RSA_set0_factors_t*)find_crypto_symbol(crypto_library, "RSA_set0_factors");
        OSSL_RSA_set0_crt_params = (OSSL_RSA_set0_key_t*)find_crypto_symbol(crypto_library, "RSA_set0_crt_params");
    } else {
        OSSL_RSA_set0_key = &OSSL102_RSA_set0_key;
        OSSL_RSA_set0_factors = &OSSL102_RSA_set0_factors;
        OSSL_RSA_set0_crt_params = &OSSL102_RSA_set0_crt_params;
    }
    OSSL_RSA_free = (OSSL_RSA_free_t *)find_crypto_symbol(crypto_library, "RSA_free");
    OSSL_RSA_public_decrypt = (OSSL_RSA_public_decrypt_t *)find_crypto_symbol(crypto_library, "RSA_public_decrypt");
    OSSL_RSA_private_encrypt = (OSSL_RSA_private_encrypt_t *)find_crypto_symbol(crypto_library, "RSA_private_decrypt");

    /* Load the function symbols for BIGNUM manipulation. */
    OSSL_BN_new = (OSSL_BN_new_t *)find_crypto_symbol(crypto_library, "BN_new");
    OSSL_BN_bin2bn = (OSSL_BN_bin2bn_t *)find_crypto_symbol(crypto_library, "BN_bin2bn");
    OSSL_BN_set_negative = (OSSL_BN_set_negative_t *)find_crypto_symbol(crypto_library, "BN_set_negative");
    OSSL_BN_free = (OSSL_BN_free_t *)find_crypto_symbol(crypto_library, "BN_free");
    OSSL_BN_bn2bin = (OSSL_BN_bn2bin_t *)find_crypto_symbol(crypto_library, "BN_bn2bin");
    OSSL_BN_num_bits = (OSSL_BN_num_bits_t *)find_crypto_symbol(crypto_library, "BN_num_bits");

    /* Load the functions symbols for OpenSSL EC algorithm. */
    OSSL_EC_KEY_generate_key = (OSSL_EC_KEY_generate_key_t *)find_crypto_symbol(crypto_library, "EC_KEY_generate_key");
    OSSL_EC_KEY_free = (OSSL_EC_KEY_free_t*)find_crypto_symbol(crypto_library, "EC_KEY_free");
    OSSL_ECDH_compute_key = (OSSL_ECDH_compute_key_t*)find_crypto_symbol(crypto_library, "ECDH_compute_key");
    OSSL_EC_KEY_get0_public_key = (OSSL_EC_KEY_get0_public_key_t*)find_crypto_symbol(crypto_library, "EC_KEY_get0_public_key");
    OSSL_EC_KEY_get0_private_key = (OSSL_EC_KEY_get0_private_key_t *)find_crypto_symbol(crypto_library, "EC_KEY_get0_private_key");
    OSSL_EC_KEY_new = (OSSL_EC_KEY_new_t*)find_crypto_symbol(crypto_library, "EC_KEY_new");
    OSSL_EC_KEY_set_public_key_affine_coordinates = (OSSL_EC_KEY_set_public_key_affine_coordinates_t*)find_crypto_symbol(crypto_library, "EC_KEY_set_public_key_affine_coordinates");
    OSSL_EC_KEY_set_private_key = (OSSL_EC_KEY_set_private_key_t*)find_crypto_symbol(crypto_library, "EC_KEY_set_private_key");
    OSSL_BN_CTX_new = (OSSL_BN_CTX_new_t*)find_crypto_symbol(crypto_library, "BN_CTX_new");
    OSSL_EC_GROUP_new_curve_GFp = (OSSL_EC_GROUP_new_curve_GFp_t*)find_crypto_symbol(crypto_library, "EC_GROUP_new_curve_GFp");
    OSSL_EC_GROUP_new_curve_GF2m = (OSSL_EC_GROUP_new_curve_GF2m_t*)find_crypto_symbol(crypto_library, "EC_GROUP_new_curve_GF2m");
    OSSL_EC_KEY_set_group = (OSSL_EC_KEY_set_group_t*)find_crypto_symbol(crypto_library, "EC_KEY_set_group");
    OSSL_EC_POINT_new = (OSSL_EC_POINT_new_t*)find_crypto_symbol(crypto_library, "EC_POINT_new");
    OSSL_EC_GROUP_set_generator = (OSSL_EC_GROUP_set_generator_t*)find_crypto_symbol(crypto_library, "EC_GROUP_set_generator");
    OSSL_EC_KEY_get0_group = (OSSL_EC_KEY_get0_group_t*)find_crypto_symbol(crypto_library, "EC_KEY_get0_group");
    OSSL_EC_POINT_free = (OSSL_EC_POINT_free_t*)find_crypto_symbol(crypto_library, "EC_POINT_free");
    OSSL_EC_GROUP_free = (OSSL_EC_GROUP_free_t*)find_crypto_symbol(crypto_library, "EC_GROUP_free");
    OSSL_BN_CTX_free = (OSSL_BN_CTX_free_t*)find_crypto_symbol(crypto_library, "BN_CTX_free");
    OSSL_EC_KEY_set_public_key = (OSSL_EC_KEY_set_public_key_t*)find_crypto_symbol(crypto_library, "EC_KEY_set_public_key");
    OSSL_EC_KEY_check_key = (OSSL_EC_KEY_check_key_t*)find_crypto_symbol(crypto_library, "EC_KEY_check_key");
    OSSL_EC_POINT_set_affine_coordinates_GFp = (OSSL_EC_POINT_set_affine_coordinates_GFp_t*)find_crypto_symbol(crypto_library, "EC_POINT_set_affine_coordinates");
    OSSL_EC_POINT_get_affine_coordinates_GFp = (OSSL_EC_POINT_get_affine_coordinates_GFp_t *)find_crypto_symbol(crypto_library, "EC_POINT_get_affine_coordinates");
    if (NULL == OSSL_EC_KEY_set_public_key_affine_coordinates) {
        /* method missing in OpenSSL version 1.0.0 */
        EC_set_public_key = &setECPublicKey;
    } else {
        EC_set_public_key = &setECPublicCoordinates;
    }
    if (NULL == OSSL_EC_POINT_set_affine_coordinates_GFp) {
        /* deprecated in OpenSSL version 1.1.1 */
        OSSL_EC_POINT_set_affine_coordinates_GFp = (OSSL_EC_POINT_set_affine_coordinates_GFp_t*)find_crypto_symbol(crypto_library, "EC_POINT_set_affine_coordinates_GFp");
        OSSL_EC_POINT_set_affine_coordinates_GF2m = (OSSL_EC_POINT_set_affine_coordinates_GF2m_t*)find_crypto_symbol(crypto_library, "EC_POINT_set_affine_coordinates_GF2m");
    } else {
        OSSL_EC_POINT_set_affine_coordinates_GF2m = (OSSL_EC_POINT_set_affine_coordinates_GF2m_t*)find_crypto_symbol(crypto_library, "EC_POINT_set_affine_coordinates");
    }
    if (NULL == OSSL_EC_POINT_get_affine_coordinates_GFp) {
        /* deprecated in OpenSSL version 1.1.1 */
        OSSL_EC_POINT_get_affine_coordinates_GFp = (OSSL_EC_POINT_get_affine_coordinates_GFp_t *)find_crypto_symbol(crypto_library, "EC_POINT_get_affine_coordinates_GFp");
        OSSL_EC_POINT_get_affine_coordinates_GF2m = (OSSL_EC_POINT_get_affine_coordinates_GF2m_t *)find_crypto_symbol(crypto_library, "EC_POINT_get_affine_coordinates_GF2m");
    } else {
        OSSL_EC_POINT_get_affine_coordinates_GF2m = (OSSL_EC_POINT_get_affine_coordinates_GF2m_t *)OSSL_EC_POINT_get_affine_coordinates_GFp;
    }
    if ((NULL == OSSL_EC_GROUP_new_curve_GF2m)
    || (NULL == OSSL_EC_POINT_set_affine_coordinates_GF2m)
    || (NULL == OSSL_EC_POINT_get_affine_coordinates_GF2m)
    ) {
        /* the OPENSSL_NO_EC2M flag is set and the EC2m methods are unavailable */
        OSSL_ECGF2M = JNI_FALSE;
    } else {
        OSSL_ECGF2M = JNI_TRUE;
    }

    /* Load the functions symbols for OpenSSL XDH and ECDSA algorithms. (Need OpenSSL 1.1.x or above). */
    if (ossl_ver >= OPENSSL_VERSION_1_1_1) {
        OSSL_EVP_PKEY_CTX_new = (OSSL_EVP_PKEY_CTX_new_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_CTX_new");
        OSSL_EVP_PKEY_CTX_new_id = (OSSL_EVP_PKEY_CTX_new_id_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_CTX_new_id");
        OSSL_EVP_PKEY_keygen_init = (OSSL_EVP_PKEY_keygen_init_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_keygen_init");
        OSSL_EVP_PKEY_keygen = (OSSL_EVP_PKEY_keygen_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_keygen");
        OSSL_EVP_PKEY_CTX_free = (OSSL_EVP_PKEY_CTX_free_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_CTX_free");
        OSSL_EVP_PKEY_get_raw_private_key = (OSSL_EVP_PKEY_get_raw_private_key_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_get_raw_private_key");
        OSSL_EVP_PKEY_get_raw_public_key = (OSSL_EVP_PKEY_get_raw_public_key_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_get_raw_public_key");
        OSSL_EVP_PKEY_new_raw_private_key = (OSSL_EVP_PKEY_new_raw_private_key_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_new_raw_private_key");
        OSSL_EVP_PKEY_new_raw_public_key = (OSSL_EVP_PKEY_new_raw_public_key_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_new_raw_public_key");
        OSSL_EVP_PKEY_derive_init = (OSSL_EVP_PKEY_derive_init_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_derive_init");
        OSSL_EVP_PKEY_derive_set_peer = (OSSL_EVP_PKEY_derive_set_peer_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_derive_set_peer");
        OSSL_EVP_PKEY_derive = (OSSL_EVP_PKEY_derive_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_derive");
        OSSL_EVP_PKEY_free = (OSSL_EVP_PKEY_free_t *)find_crypto_symbol(crypto_library, "EVP_PKEY_free");

        OSSL_ECDSA_do_sign = (OSSL_ECDSA_do_sign_t *)find_crypto_symbol(crypto_library, "ECDSA_do_sign");
        OSSL_ECDSA_do_verify = (OSSL_ECDSA_do_verify_t *)find_crypto_symbol(crypto_library, "ECDSA_do_verify");
        OSSL_ECDSA_SIG_new = (OSSL_ECDSA_SIG_new_t *)find_crypto_symbol(crypto_library, "ECDSA_SIG_new");
        OSSL_ECDSA_SIG_free = (OSSL_ECDSA_SIG_free_t *)find_crypto_symbol(crypto_library, "ECDSA_SIG_free");
        OSSL_ECDSA_SIG_get0_r = (OSSL_ECDSA_SIG_get0_r_t *)find_crypto_symbol(crypto_library, "ECDSA_SIG_get0_r");
        OSSL_ECDSA_SIG_get0_s = (OSSL_ECDSA_SIG_get0_s_t *)find_crypto_symbol(crypto_library, "ECDSA_SIG_get0_s");
        OSSL_ECDSA_SIG_set0 = (OSSL_ECDSA_SIG_set0_t *)find_crypto_symbol(crypto_library, "ECDSA_SIG_set0");
    } else {
        OSSL_EVP_PKEY_CTX_new = NULL;
        OSSL_EVP_PKEY_CTX_new_id = NULL;
        OSSL_EVP_PKEY_keygen_init = NULL;
        OSSL_EVP_PKEY_keygen = NULL;
        OSSL_EVP_PKEY_CTX_free = NULL;
        OSSL_EVP_PKEY_get_raw_private_key = NULL;
        OSSL_EVP_PKEY_get_raw_public_key = NULL;
        OSSL_EVP_PKEY_new_raw_private_key = NULL;
        OSSL_EVP_PKEY_new_raw_public_key = NULL;
        OSSL_EVP_PKEY_derive_init = NULL;
        OSSL_EVP_PKEY_derive_set_peer = NULL;
        OSSL_EVP_PKEY_derive = NULL;
        OSSL_EVP_PKEY_free = NULL;

        OSSL_ECDSA_do_sign = NULL;
        OSSL_ECDSA_do_verify = NULL;
        OSSL_ECDSA_SIG_new = NULL;
        OSSL_ECDSA_SIG_free = NULL;
        OSSL_ECDSA_SIG_get0_r = NULL;
        OSSL_ECDSA_SIG_get0_s = NULL;
        OSSL_ECDSA_SIG_set0 = NULL;
    }

    /* Load the functions symbols for OpenSSL PBE algorithm. */
    OSSL_PKCS12_key_gen = (OSSL_PKCS12_key_gen_t*)find_crypto_symbol(crypto_library, "PKCS12_key_gen_uni");

    if ((NULL == OSSL_error_string) ||
        (NULL == OSSL_error_string_n) ||
        (NULL == OSSL_get_error) ||
        (NULL == OSSL_sha1) ||
        (NULL == OSSL_sha256) ||
        (NULL == OSSL_sha224) ||
        (NULL == OSSL_sha384) ||
        (NULL == OSSL_sha512) ||
        (NULL == OSSL_MD_CTX_new) ||
        (NULL == OSSL_MD_CTX_reset) ||
        (NULL == OSSL_MD_CTX_free) ||
        (NULL == OSSL_DigestInit_ex) ||
        (NULL == OSSL_MD_CTX_copy_ex) ||
        (NULL == OSSL_DigestUpdate) ||
        (NULL == OSSL_DigestFinal_ex) ||
        (NULL == OSSL_CIPHER_CTX_new) ||
        (NULL == OSSL_CIPHER_CTX_free) ||
        (NULL == OSSL_aes_128_cbc) ||
        (NULL == OSSL_aes_192_cbc) ||
        (NULL == OSSL_aes_256_cbc) ||
        (NULL == OSSL_CipherInit_ex) ||
        (NULL == OSSL_CIPHER_CTX_set_padding) ||
        (NULL == OSSL_CipherUpdate) ||
        (NULL == OSSL_CipherFinal_ex) ||
        (NULL == OSSL_aes_128_gcm) ||
        (NULL == OSSL_aes_192_gcm) ||
        (NULL == OSSL_aes_256_gcm) ||
        (NULL == OSSL_CIPHER_CTX_ctrl) ||
        (NULL == OSSL_DecryptInit_ex) ||
        (NULL == OSSL_DecryptUpdate) ||
        (NULL == OSSL_DecryptFinal) ||
        (NULL == OSSL_RSA_new) ||
        (NULL == OSSL_RSA_set0_key) ||
        (NULL == OSSL_RSA_set0_factors) ||
        (NULL == OSSL_RSA_set0_crt_params) ||
        (NULL == OSSL_RSA_free) ||
        (NULL == OSSL_RSA_public_decrypt) ||
        (NULL == OSSL_RSA_private_encrypt) ||
        (NULL == OSSL_BN_new) ||
        (NULL == OSSL_BN_bin2bn) ||
        (NULL == OSSL_BN_set_negative) ||
        (NULL == OSSL_BN_free) ||
        (NULL == OSSL_BN_bn2bin) ||
        (NULL == OSSL_BN_num_bits) ||
        (NULL == OSSL_EC_KEY_generate_key) ||
        (NULL == OSSL_EC_KEY_free) ||
        (NULL == OSSL_ECDH_compute_key) ||
        (NULL == OSSL_EC_KEY_get0_public_key) ||
        (NULL == OSSL_EC_KEY_get0_private_key) ||
        (NULL == OSSL_EC_KEY_new) ||
        (NULL == OSSL_EC_KEY_set_private_key) ||
        (NULL == OSSL_BN_CTX_new) ||
        (NULL == OSSL_EC_GROUP_new_curve_GFp) ||
        (NULL == OSSL_EC_KEY_set_group) ||
        (NULL == OSSL_EC_POINT_new) ||
        (NULL == OSSL_EC_POINT_set_affine_coordinates_GFp) ||
        (NULL == OSSL_EC_POINT_get_affine_coordinates_GFp) ||
        (NULL == OSSL_EC_GROUP_set_generator) ||
        (NULL == OSSL_EC_KEY_get0_group) ||
        (NULL == OSSL_EC_POINT_free) ||
        (NULL == OSSL_EC_GROUP_free) ||
        (NULL == OSSL_BN_CTX_free) ||
        (NULL == OSSL_EC_KEY_set_public_key) ||
        (NULL == OSSL_EC_KEY_check_key) ||
        (NULL == OSSL_PKCS12_key_gen) ||
        /* Check symbols that are only available in OpenSSL 1.1.1 and above. */
        ((ossl_ver >= OPENSSL_VERSION_1_1_1) &&
            ((NULL == OSSL_EVP_PKEY_get_raw_private_key) ||
             (NULL == OSSL_EVP_PKEY_get_raw_public_key) ||
             (NULL == OSSL_EVP_PKEY_new_raw_private_key) ||
             (NULL == OSSL_EVP_PKEY_new_raw_public_key) ||
             (NULL == OSSL_EVP_PKEY_CTX_new) ||
             (NULL == OSSL_EVP_PKEY_CTX_new_id) ||
             (NULL == OSSL_EVP_PKEY_keygen_init) ||
             (NULL == OSSL_EVP_PKEY_keygen) ||
             (NULL == OSSL_EVP_PKEY_CTX_free) ||
             (NULL == OSSL_EVP_PKEY_derive_init) ||
             (NULL == OSSL_EVP_PKEY_derive_set_peer) ||
             (NULL == OSSL_EVP_PKEY_derive) ||
             (NULL == OSSL_EVP_PKEY_free) ||
             (NULL == OSSL_ECDSA_do_sign) ||
             (NULL == OSSL_ECDSA_do_verify) ||
             (NULL == OSSL_ECDSA_SIG_new) ||
             (NULL == OSSL_ECDSA_SIG_free) ||
             (NULL == OSSL_ECDSA_SIG_get0_r) ||
             (NULL == OSSL_ECDSA_SIG_get0_s) ||
             (NULL == OSSL_ECDSA_SIG_set0))) ||
        /* Check symbols that are only available in OpenSSL 1.1.x and above */
        ((ossl_ver >= OPENSSL_VERSION_1_1_0) && ((NULL == OSSL_chacha20) || (NULL == OSSL_chacha20_poly1305))) ||
        /* Check symbols that are only available in OpenSSL 1.0.x and above */
        ((NULL == OSSL_CRYPTO_num_locks) && (ossl_ver < OPENSSL_VERSION_1_1_0)) ||
        ((NULL == OSSL_CRYPTO_THREADID_set_numeric) && (ossl_ver < OPENSSL_VERSION_1_1_0)) ||
        ((NULL == OSSL_OPENSSL_malloc) && (ossl_ver < OPENSSL_VERSION_1_1_0)) ||
        ((NULL == OSSL_OPENSSL_free) && (ossl_ver < OPENSSL_VERSION_1_1_0)) ||
        ((NULL == OSSL_CRYPTO_THREADID_set_callback) && (ossl_ver < OPENSSL_VERSION_1_1_0)) ||
        ((NULL == OSSL_CRYPTO_set_locking_callback) && (ossl_ver < OPENSSL_VERSION_1_1_0))
    ) {
        if (traceEnabled) {
            fprintf(stderr, "Error loading OpenSSL: One or more of the required symbols are missing.");
        }
        unload_crypto_library(crypto_library);
        crypto_library = NULL;
        return -1;
    } else {
        if (ossl_ver < OPENSSL_VERSION_1_1_0) {
            if (0 != thread_setup()) {
                if (traceEnabled) {
                    fprintf(stderr, "Error loading OpenSSL: Thread setup was unsuccessful.");
                }
                unload_crypto_library(crypto_library);
                crypto_library = NULL;
                return -1;
            }
        }
        if (traceEnabled) {
            fprintf(stderr, "OpenSSL library loaded successfully.\n");
        }
        return ossl_ver;
    }
}

#if defined(WINDOWS)
static HANDLE *lock_cs = NULL;

int thread_setup()
{
    int i = 0;
    int j = 0;
    int lockNum = (*OSSL_CRYPTO_num_locks)();
    size_t size = lockNum * sizeof(HANDLE);
    lock_cs = (*OSSL_OPENSSL_malloc)(size);
    if (NULL == lock_cs) {
        return -1;
    }
    for (i = 0; i < lockNum; i++) {
        lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
        if (NULL == lock_cs[i]) {
            fprintf(stderr, "CreateMutex error: %d\n", GetLastError());
            for (j = 0; j < i; j++) {
                BOOL closeResult = CloseHandle(lock_cs[j]);
                if (FALSE == closeResult) {
                    fprintf(stderr, "CloseHandle error: %d\n", GetLastError());
                }
            }
            (*OSSL_OPENSSL_free)(lock_cs);
            lock_cs = NULL;
            return -1;
        }
    }
    /*
     * For windows platform, OpenSSL already has an implementation to get thread id.
     * So Windows do not need (*OSSL_CRYPTO_THREADID_set_callback)() here like non-Windows Platform.
     */
    (*OSSL_CRYPTO_set_locking_callback)(win32_locking_callback);
    return 0;
}

void win32_locking_callback(int mode, int type, const char *file, int line)
{
    if (0 != (mode & CRYPTO_LOCK)) {
        DWORD dwWaitResult = WaitForSingleObject(lock_cs[type], INFINITE);
        if (WAIT_FAILED == dwWaitResult) {
            fprintf(stderr, "WaitForSingleObject error: %d\n", GetLastError());
        }
    } else {
        BOOL releaseResult = ReleaseMutex(lock_cs[type]);
        if (FALSE == releaseResult) {
            fprintf(stderr, "ReleaseMutex error: %d\n", GetLastError());
        }
    }
}

#else /* defined(WINDOWS) */
static pthread_mutex_t *lock_cs = NULL;

int thread_setup()
{
    int i = 0;
    int j = 0;
    int lockNum = (*OSSL_CRYPTO_num_locks)();
    size_t size = lockNum * sizeof(pthread_mutex_t);
    lock_cs = (*OSSL_OPENSSL_malloc)(size);
    if (NULL == lock_cs) {
        return -1;
    }
    for (i = 0; i < lockNum; i++) {
        int initResult = pthread_mutex_init(&(lock_cs[i]), NULL);
        if (0 != initResult) {
            fprintf(stderr, "pthread_mutex_init error %d\n", initResult);
            for (j = 0; j < i; j++) {
                int destroyResult = pthread_mutex_destroy(&(lock_cs[j]));
                if (0 != destroyResult) {
                    fprintf(stderr, "pthread_mutex_destroy error %d\n", destroyResult);
                }
            }
            (*OSSL_OPENSSL_free)(lock_cs);
            lock_cs = NULL;
            return -1;
        }
    }
    (*OSSL_CRYPTO_THREADID_set_callback)(pthreads_thread_id);
    (*OSSL_CRYPTO_set_locking_callback)(pthreads_locking_callback);
    return 0;
}

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
    if (0 != (mode & CRYPTO_LOCK)) {
        int lockResult = pthread_mutex_lock(&(lock_cs[type]));
        if (0 != lockResult) {
            fprintf(stderr, "pthread_mutex_lock error: %d\n", lockResult);
        }
    } else {
        int unlockResult = pthread_mutex_unlock(&(lock_cs[type]));
        if (0 != unlockResult) {
            fprintf(stderr, "pthread_mutex_unlock error: %d\n", unlockResult);
        }
    }
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{
    (*OSSL_CRYPTO_THREADID_set_numeric)(tid, (unsigned long)pthread_self());
}
#endif /* defined(WINDOWS) */

/* Clean up resource from loadCrypto() and thread_setup()*/
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM * vm, void * reserved)
{
    int i = 0;
    int lockNum = 0;
    if (NULL == crypto_library) {
        return;
    }
    if ((NULL == OSSL_CRYPTO_num_locks) || (NULL == lock_cs)) {
        unload_crypto_library(crypto_library);
        crypto_library = NULL;
        return;
    }
    lockNum = (*OSSL_CRYPTO_num_locks)();
    (*OSSL_CRYPTO_set_locking_callback)(NULL);
    for (i = 0; i < lockNum; i++) {
#if defined(WINDOWS)
        BOOL destoryResult = CloseHandle(lock_cs[i]);
        if (FALSE == destoryResult) {
            fprintf(stderr, "destoryResult error: %d\n", GetLastError());
        }
#else /* defined(WINDOWS) */
        int destroyResult = pthread_mutex_destroy(&(lock_cs[i]));
        if (0 != destroyResult) {
            fprintf(stderr, "pthread_mutex_destroy error %d\n", destroyResult);
        }
#endif /* defined(WINDOWS) */
    }
    (*OSSL_OPENSSL_free)(lock_cs);
    lock_cs = NULL;
    unload_crypto_library(crypto_library);
    crypto_library = NULL;
}

/* Check whether MD5 is available.
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    isMD5Available
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_isMD5Available
  (JNIEnv *env, jclass thisClass)
{
    return (NULL != OSSL_md5) ? JNI_TRUE : JNI_FALSE;
}

/* Create Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestCreateContext
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestCreateContext
  (JNIEnv *env, jclass thisObj, jlong copyContext, jint algoIdx)
{
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *digestAlg = NULL;
    OpenSSLMDContext *context = NULL;

    switch (algoIdx) {
        case jdk_crypto_jniprovider_NativeCrypto_MD5:
            digestAlg = (*OSSL_md5)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA1_160:
            digestAlg = (*OSSL_sha1)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA2_224:
            digestAlg = (*OSSL_sha224)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA2_256:
            digestAlg = (*OSSL_sha256)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA5_384:
            digestAlg = (*OSSL_sha384)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA5_512:
            digestAlg = (*OSSL_sha512)();
            break;
        default:
            return -1;
    }

    if (NULL == (ctx = (*OSSL_MD_CTX_new)())) {
        printErrors();
        return -1;
    }

    if (1 != (*OSSL_DigestInit_ex)(ctx, digestAlg, NULL)) {
        printErrors();
        (*OSSL_MD_CTX_free)(ctx);
        return -1;
    }

    context = malloc(sizeof(OpenSSLMDContext));
    if (NULL == context) {
        (*OSSL_MD_CTX_free)(ctx);
        return -1;
    }
    context->ctx = ctx;
    context->digestAlg = digestAlg;

    /*
     * Create a second initialized openssl digest context. This is being done for performance reasons since
     * creating and or re-initializing digest contexts later during processing is found to be expensive.
     * This second context, context->cachedInitializedDigestContext, will be copied over the working context,
     * context->ctx, using the EVP_MD_CTX_copy_ex API whenever we wish to re-initalize this cipher. This occurs
     * during an explicit reset of the cipher or whenever a final digest is computed.
     */
    context->cachedInitializedDigestContext = (*OSSL_MD_CTX_new)();
    if (NULL == context->cachedInitializedDigestContext) {
        goto releaseContexts;
    }

    if (1 != (*OSSL_MD_CTX_copy_ex)(context->cachedInitializedDigestContext, context->ctx)) {
        goto releaseContexts;
    }

    if (0 != copyContext) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*)(intptr_t)copyContext)->ctx;
        if (NULL == contextToCopy) {
            goto releaseContexts;
        }
        if (0 == (*OSSL_MD_CTX_copy_ex)(ctx, contextToCopy)) {
            goto releaseContexts;
        }
    }

    return (jlong)(intptr_t)context;

releaseContexts:
    printErrors();
    Java_jdk_crypto_jniprovider_NativeCrypto_DigestDestroyContext(env, thisObj, (jlong)(intptr_t)context);
    return -1;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestDestroyContext
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c)
{
    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;
    if (NULL == context) {
        return -1;
    }

    if (NULL != context->ctx) {
        (*OSSL_MD_CTX_free)(context->ctx);
        context->ctx = NULL;
    }

    if (NULL != context->cachedInitializedDigestContext) {
        (*OSSL_MD_CTX_free)(context->cachedInitializedDigestContext);
        context->cachedInitializedDigestContext = NULL;
    }

    free(context);
    return 0;
}

/* Update Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestUpdate
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset,
  jint messageLen)
{
    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;
    unsigned char* messageNative = NULL;

    if (NULL == context) {
        return -1;
    }
    if (NULL == message) {
        return -1;
    }

    messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
    if (NULL == messageNative) {
        return -1;
    }

    if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);

    return 0;
}

/* Compute and Reset Digest
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestComputeAndReset
 * Signature: (J[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestComputeAndReset
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset, jint messageLen,
  jbyteArray digest, jint digestOffset, jint digestLen)
{
    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;

    unsigned int size = 0;
    unsigned char* messageNative = NULL;
    unsigned char* digestNative = NULL;

    if ((NULL == context) || (NULL == context->ctx) || (NULL == context->cachedInitializedDigestContext)) {
        return -1;
    }

    if (NULL != message) {
        messageNative = (*env)->GetPrimitiveArrayCritical(env, message, 0);
        if (NULL == messageNative) {
            return -1;
        }

        if (1 != (*OSSL_DigestUpdate)(context->ctx, (messageNative + messageOffset), messageLen)) {
            printErrors();
            (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
            return -1;
        }

        (*env)->ReleasePrimitiveArrayCritical(env, message, messageNative, JNI_ABORT);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest, 0);
    if (NULL == digestNative) {
        return -1;
    }

    if (1 != (*OSSL_DigestFinal_ex)(context->ctx, (digestNative + digestOffset), &size)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, digest, digestNative, 0);

    /*
     * Reset the message digest context to the original context. We are then ready to perform
     * digest operations again using a copy of this cached context.
     */
    if (1 != (*OSSL_MD_CTX_copy_ex)(context->ctx, context->cachedInitializedDigestContext)) {
        printErrors();

        if (NULL != context->ctx) {
            (*OSSL_MD_CTX_free)(context->ctx);
            context->ctx = NULL;
        }

        if (NULL != context->cachedInitializedDigestContext) {
            (*OSSL_MD_CTX_free)(context->cachedInitializedDigestContext);
            context->cachedInitializedDigestContext = NULL;
        }

        return -1;
    }

    return (jint)size;
}

/* Reset Digest
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestReset
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestReset
  (JNIEnv *env, jclass thisObj, jlong c)
{
    OpenSSLMDContext *context = (OpenSSLMDContext*)(intptr_t) c;

    if ((NULL == context) || (NULL == context->ctx) || (NULL == context->cachedInitializedDigestContext)) {
        return -1;
    }

    /*
     * Reset the message digest context to the original context. We are then ready to perform
     * digest operations again using a copy of this cached context.
     */
    if (1 != (*OSSL_MD_CTX_copy_ex)(context->ctx, context->cachedInitializedDigestContext)) {
        printErrors();

        if (NULL != context->ctx) {
            (*OSSL_MD_CTX_free)(context->ctx);
            context->ctx = NULL;
        }

        if (NULL != context->cachedInitializedDigestContext) {
            (*OSSL_MD_CTX_free)(context->cachedInitializedDigestContext);
            context->cachedInitializedDigestContext = NULL;
        }

        return -1;
    }

    return 0;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CreateContext
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CreateContext
  (JNIEnv *env, jclass thisObj)
{
    EVP_CIPHER_CTX *ctx = NULL;

    /* Create and initialise the context */
    if (NULL == (ctx = (*OSSL_CIPHER_CTX_new)())) {
        printErrors();
        return -1;
    }

    return (jlong)(intptr_t)ctx;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DestroyContext
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DestroyContext
  (JNIEnv *env, jclass thisObj, jlong c)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    if (NULL == ctx) {
        return -1;
    }

    (*OSSL_CIPHER_CTX_free)(ctx);
    return 0;
}

/* Initialize CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCInit
 * Signature: (JI[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCInit
  (JNIEnv *env, jclass thisObj, jlong c, jint mode, jbyteArray iv, jint iv_len,
  jbyteArray key, jint key_len, jboolean doReset)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    unsigned char* ivNative = NULL;
    unsigned char* keyNative = NULL;
    const EVP_CIPHER * evp_cipher1 = NULL;

    if (NULL == ctx) {
        return -1;
    }

    if (JNI_FALSE == doReset) {
        switch (key_len) {
            case 16:
                evp_cipher1 = (*OSSL_aes_128_cbc)();
                break;
            case 24:
                evp_cipher1 = (*OSSL_aes_192_cbc)();
                break;
            case 32:
                evp_cipher1 = (*OSSL_aes_256_cbc)();
                break;
            default:
                break;
        }
    }

    ivNative = (unsigned char*)((*env)->GetByteArrayElements(env, iv, 0));
    if (NULL == ivNative) {
        return -1;
    }

    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, 0));
    if (NULL == keyNative) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_cipher1, NULL, keyNative, ivNative, mode)) {
        printErrors();
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
        return -1;
    }

    if (JNI_FALSE == doReset) {
        (*OSSL_CIPHER_CTX_set_padding)(ctx, 0);
    }

    (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
    return 0;
}

/* Update CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCUpdate
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    int outputLen = 0;

    unsigned char* inputNative;
    unsigned char* outputNative;

    if (NULL == ctx) {
        return -1;
    }

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)outputLen;
}

/* CBC Final Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCFinalEncrypt
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCFinalEncrypt
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    if (NULL == ctx) {
        return -1;
    }

    unsigned char buf[16];

    int outputLen = -1;
    int outputLen1 = -1;

    unsigned char* inputNative;
    unsigned char* outputNative;

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherFinal_ex)(ctx, buf, &outputLen1)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)(outputLen + outputLen1);
}

int first_time_gcm = 0;

/* GCM Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMEncrypt
 * Signature: (J[BI[BI[BII[BI[BIIZZ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMEncrypt
  (JNIEnv * env, jclass obj, jlong context, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen, jboolean newIVLen, jboolean newKeyLen)
{
    jint ret = -1;

    int len = 0;
    int len_cipher = 0;
    unsigned char *keyNative = NULL;
    unsigned char *ivNative = NULL;
    unsigned char *inputNative = NULL;
    unsigned char *outputNative = NULL;
    unsigned char *aadNative = NULL;

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(intptr_t) context;
    const EVP_CIPHER *evp_gcm_cipher = NULL;

    if (NULL == ctx) {
        printErrors();
        goto cleanup;
    }

    if (newKeyLen) {
        switch (keyLen) {
        case 16:
            evp_gcm_cipher = (*OSSL_aes_128_gcm)();
            break;
        case 24:
            evp_gcm_cipher = (*OSSL_aes_192_gcm)();
            break;
        case 32:
            evp_gcm_cipher = (*OSSL_aes_256_gcm)();
            break;
        default:
            break;
        }

        if (1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, OPENSSL_SAME_MODE)) {
            printErrors();
            goto cleanup;
        }
    }

    if (newIVLen) {
        if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
            printErrors();
            goto cleanup;
        }
    }

    /* Initialize context with key and IV. */
    keyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (NULL == keyNative) {
        goto cleanup;
    }

    ivNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (NULL == ivNative) {
        goto cleanup;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, NULL, NULL, keyNative, ivNative, OPENSSL_ENCRYPTION_MODE)) {
        printErrors();
        goto cleanup;
    }

    /* Provide AAD. */
    aadNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
    if (NULL == aadNative) {
        goto cleanup;
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, NULL, &len, aadNative, aadLen)) {
        printErrors();
        goto cleanup;
    }

    outputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        goto cleanup;
    }

    /* Encrypt plaintext, if available and obtain ciphertext. */
    if (inLen > 0) {
        inputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (NULL == inputNative) {
            goto cleanup;
        }

        if (1 != (*OSSL_CipherUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen)) {
            printErrors();
            goto cleanup;
        }
        len_cipher = len;
    }

    /* Finalize the encryption. */
    if (1 != (*OSSL_CipherFinal_ex)(ctx, outputNative + outOffset + len_cipher, &len)) {
        printErrors();
        goto cleanup;
    }
    len_cipher += len;

    /* Get the tag, place it at the end of the cipherText buffer. */
    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len_cipher)) {
        printErrors();
        goto cleanup;
    }

    ret = (jint)len_cipher;

cleanup:
    if (NULL != inputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    }
    if (NULL != outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
    }
    if (NULL != aadNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
    }
    if (NULL != ivNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
    }
    if (NULL != keyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
    }

    return ret;
}

/* GCM Decryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMDecrypt
 * Signature: (J[BI[BI[BII[BI[BIIZZ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMDecrypt
  (JNIEnv * env, jclass obj, jlong context, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen, jboolean newIVLen, jboolean newKeyLen)
{
    jint ret = -1;

    int len = 0;
    int plaintext_len = 0;
    unsigned char *keyNative = NULL;
    unsigned char *ivNative = NULL;
    unsigned char *aadNative = NULL;
    unsigned char *inputNative = NULL;
    unsigned char *outputNative = NULL;

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(intptr_t) context;
    const EVP_CIPHER *evp_gcm_cipher = NULL;

    if (NULL == ctx) {
        printErrors();
        goto cleanup;
    }

    if (newKeyLen) {
        switch (keyLen) {
        case 16:
            evp_gcm_cipher = (*OSSL_aes_128_gcm)();
            break;
        case 24:
            evp_gcm_cipher = (*OSSL_aes_192_gcm)();
            break;
        case 32:
            evp_gcm_cipher = (*OSSL_aes_256_gcm)();
            break;
        default:
            break;
        }

        if (1 != (*OSSL_CipherInit_ex)(ctx, evp_gcm_cipher, NULL, NULL, NULL, OPENSSL_DECRYPTION_MODE)) {
            printErrors();
            goto cleanup;
        }
    }

    if (newIVLen) {
        if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL)) {
            printErrors();
            goto cleanup;
        }
    }

    /* Initialise context with key and IV. */
    keyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (NULL == keyNative) {
        goto cleanup;
    }

    ivNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, iv, 0));
    if (NULL == ivNative) {
        goto cleanup;
    }

    if (0 == (*OSSL_DecryptInit_ex)(ctx, NULL, NULL, keyNative, ivNative)) {
        printErrors();
        goto cleanup;
    }

    /* Provide any AAD data. */
    if (aadLen > 0) {
        aadNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
        if (NULL == aadNative) {
            goto cleanup;
        }

        if (0 == (*OSSL_DecryptUpdate)(ctx, NULL, &len, aadNative, aadLen)) {
            printErrors();
            goto cleanup;
        }
    }

    outputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        goto cleanup;
    }

    if (inLen > 0) {
        inputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, input, 0));
        if (NULL == inputNative) {
            goto cleanup;
        }
    }

    if (inLen - tagLen > 0) {
        if (0 == (*OSSL_DecryptUpdate)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen)) {
            printErrors();
            goto cleanup;
        }
        plaintext_len = len;
    }

    if (0 == (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen)) {
        printErrors();
        goto cleanup;
    }

    if (0 < (*OSSL_DecryptFinal)(ctx, outputNative + outOffset + len, &len)) {
        /* Decryption was successful. */
        plaintext_len += len;
        ret = (jint)plaintext_len;
    } else {
        /* There was a tag mismatch. */
        ret = -2;
    }

cleanup:
    if (NULL != inputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    }
    if (NULL != outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);
    }
    if (NULL != aadNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
    }
    if (NULL != ivNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, JNI_ABORT);
    }
    if (NULL != keyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, JNI_ABORT);
    }

    return ret;
}

BIGNUM* convertJavaBItoBN(unsigned char* in, int len);

/* Create an RSA Public Key
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    createRSAPublicKey
 * Signature: ([BI[BI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_createRSAPublicKey
  (JNIEnv *env, jclass obj, jbyteArray n, jint nLen, jbyteArray e, jint eLen)
{
    unsigned char* nNative = NULL;
    unsigned char* eNative = NULL;
    RSA* publicRSAKey = NULL;
    BIGNUM* nBN = NULL;
    BIGNUM* eBN = NULL;
    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (NULL == nNative) {
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (NULL == eNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        return -1;
    }

    publicRSAKey = (*OSSL_RSA_new)();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);

    if ((NULL == publicRSAKey) || (NULL == nBN) || (NULL == eBN)) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_key)(publicRSAKey, nBN, eBN, NULL);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);

    if (0 == ret) {
        return -1;
    }

    return (jlong)(intptr_t)publicRSAKey;
}

/* Create an RSA Private CRT Key
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    createRSAPrivateCrtKey
 * Signature: ([BI[BI[BI[BI[BI[BI[BI[BI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_createRSAPrivateCrtKey
  (JNIEnv *env, jclass obj, jbyteArray n, jint nLen, jbyteArray d, jint dLen, jbyteArray e, jint eLen, jbyteArray p, jint pLen, jbyteArray q, jint qLen, jbyteArray dp, jint dpLen, jbyteArray dq, jint dqLen, jbyteArray qinv, jint qinvLen)
{
    unsigned char* nNative = NULL;
    unsigned char* dNative = NULL;
    unsigned char* eNative = NULL;
    unsigned char* pNative = NULL;
    unsigned char* qNative = NULL;
    unsigned char* dpNative = NULL;
    unsigned char* dqNative = NULL;
    unsigned char* qinvNative = NULL;
    RSA* privateRSACrtKey = NULL;
    BIGNUM* nBN = NULL;
    BIGNUM* eBN = NULL;
    BIGNUM* dBN = NULL;
    BIGNUM* pBN = NULL;
    BIGNUM* qBN = NULL;
    BIGNUM* dpBN = NULL;
    BIGNUM* dqBN = NULL;
    BIGNUM* qinvBN = NULL;

    int ret = 0;

    nNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (NULL == nNative) {
        return -1;
    }

    dNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, d, 0));
    if (NULL == dNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        return -1;
    }

    eNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, e, 0));
    if (NULL == eNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        return -1;
    }

    pNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, p, 0));
    if (NULL == pNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        return -1;
    }

    qNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, q, 0));
    if (NULL == qNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        return -1;
    }

    dpNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dp, 0));
    if (NULL == dpNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        return -1;
    }

    dqNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, dq, 0));
    if (NULL == dqNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        return -1;
    }

    qinvNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, qinv, 0));
    if (NULL == qinvNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        return -1;
    }

    privateRSACrtKey = (*OSSL_RSA_new)();

    nBN = convertJavaBItoBN(nNative, nLen);
    eBN = convertJavaBItoBN(eNative, eLen);
    dBN = convertJavaBItoBN(dNative, dLen);

    if (NULL == privateRSACrtKey || NULL == nBN || NULL == eBN || NULL == dBN) {

        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_key)(privateRSACrtKey, nBN, eBN, dBN);

    pBN = convertJavaBItoBN(pNative, pLen);
    qBN = convertJavaBItoBN(qNative, qLen);

    if (0 == ret || NULL == pBN || NULL == qBN) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_factors)(privateRSACrtKey, pBN, qBN);

    dpBN = convertJavaBItoBN(dpNative, dpLen);
    dqBN = convertJavaBItoBN(dqNative, dqLen);
    qinvBN = convertJavaBItoBN(qinvNative, qinvLen);

    if (0 == ret || NULL == dpBN || NULL == dqBN || NULL == qinvBN) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);
        return -1;
    }

    ret = (*OSSL_RSA_set0_crt_params)(privateRSACrtKey, dpBN, dqBN, qinvBN);

    (*env)->ReleasePrimitiveArrayCritical(env, n, nNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, d, dNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, e, eNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, p, pNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, q, qNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, dp, dpNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, dq, dqNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, qinv, qinvNative, JNI_ABORT);

    if (0 == ret) {
        return -1;
    }

    return (jlong)(intptr_t)privateRSACrtKey;
}

/* Free RSA Public/Private Key
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    destroyRSAKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_destroyRSAKey
  (JNIEnv *env, jclass obj, jlong rsaKey)
{
    RSA* rsaKey2 = (RSA*)(intptr_t)rsaKey;
    if (NULL != rsaKey2) {
        (*OSSL_RSA_free)(rsaKey2);
    }
}

/* RSAEP Cryptographic Primitive, RSA Public Key operation
 * Returns -1 on error
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    RSAEP
 * Signature: ([BI[BJ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_RSAEP
  (JNIEnv *env, jclass obj, jbyteArray k, jint kLen, jbyteArray m, jlong publicRSAKey)
{
    unsigned char* kNative = NULL;
    unsigned char* mNative = NULL;
    RSA* rsaKey = NULL;
    int msg_len = 0;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (NULL == kNative) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (NULL == mNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
        return -1;
    }

    rsaKey = (RSA*)(intptr_t)publicRSAKey;

    /* OSSL_RSA_public_decrypt returns -1 on error */
    msg_len = (*OSSL_RSA_public_decrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative, 0);
    return (jint)msg_len;
}

/* RSADP Cryptographic Primitive, RSA Private Key operation
 * Returns -1 on error
 * The param verify is -1 for 'no verify', otherwise it is size of m (with verify)
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    RSADP
 * Signature: ([BI[BIJ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_RSADP
  (JNIEnv *env, jclass obj, jbyteArray k, jint kLen, jbyteArray m, jint verify, jlong privateRSAKey)
{
    unsigned char* kNative = NULL;
    unsigned char* mNative = NULL;
    int msg_len = 0;
    int msg_len2 = 0;
    unsigned char* k2 = NULL;
    RSA* rsaKey = NULL;

    kNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, k, 0));
    if (NULL == kNative) {
        return -1;
    }

    mNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, m, 0));
    if (NULL == mNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
        return -1;
    }

    rsaKey = (RSA*)(intptr_t)privateRSAKey;

    /* OSSL_RSA_private_encrypt returns -1 on error */
    msg_len = (*OSSL_RSA_private_encrypt)(kLen, kNative, mNative, rsaKey, RSA_NO_PADDING);

    if ((-1 != verify) && (-1 != msg_len)) {
        if ((verify == kLen) || (verify == (kLen + 1))) {
            k2 = malloc(kLen * (sizeof(unsigned char)));
            if (NULL != k2) {

                /* mNative is size 'verify' */
                msg_len2 = (*OSSL_RSA_public_decrypt)(verify, mNative, k2, rsaKey, RSA_NO_PADDING);
                if (-1 != msg_len2) {

                    int i;
                    /*
                     * For certain key sizes, the decrypted message retrieved from the RSA_public_decrypt
                     * includes a 1 byte padding at the beginning of the message. In these cases, this
                     * padding must be zero. And the comparison to the original message should not include
                     * this first byte.
                     */
                    if (verify == (kLen + 1)) {
                        if (0 != k2[0]) {
                            msg_len = -2;
                        } else {
                            for (i = 0; i < kLen; i++) {
                                if (kNative[i] != k2[i + 1]) {
                                    msg_len = -2;
                                    break;
                                }
                            }
                        }
                    } else { /* if verify == kLen */
                        for (i = 0; i < verify; i++) {
                            if (kNative[i] != k2[i]) {
                                msg_len = -2;
                                break;
                            }
                        }
                    }
                } else {
                    msg_len = -1;
                }
                free(k2);
            } else {
                msg_len = -1;
            }
        } else {
            msg_len = -2;
        }
    }

    (*env)->ReleasePrimitiveArrayCritical(env, k, kNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, m, mNative, 0);

    return (jint)msg_len;
}

/*
 * Converts 2's complement representation of a big integer
 * into an OpenSSL BIGNUM
 */
BIGNUM* convertJavaBItoBN(unsigned char* in, int len)
{
    /* first bit is neg */
    int neg = (in[0] & 0x80);
    int c = 1; /* carry bit */
    int i = 0;
    BIGNUM* bn = NULL;
    if (0 != neg) {
        /* number is negative in two's complement form */
        /* need to extract magnitude */
        for (i = len - 1; i >= 0; i--) {
            in[i] ^= 0xff; /* flip bits */
            if (c) { /* add 1 for as long as needed */
                c = 0 == (++in[i]);
            }
        }
    }
    bn = (*OSSL_BN_bin2bn)(in, len, NULL);
    if (bn != NULL) {
        (*OSSL_BN_set_negative)(bn, neg);
    }
    return bn;
}

typedef struct rsa_st102 {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of aEVP_PKEY, it is set to 0
     */
    int pad;
    long version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
}OSSL102_RSA;

/*
 * Compatibility Layer for RSA algorithim using OpenSSL 1.0.2
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */
int OSSL102_RSA_set0_key(RSA *r2, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    OSSL102_RSA* r = (OSSL102_RSA *) r2;
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        (*OSSL_BN_free)(r->n);
        r->n = n;
    }
    if (e != NULL) {
        (*OSSL_BN_free)(r->e);
        r->e = e;
    }
    if (d != NULL) {
        (*OSSL_BN_free)(r->d);
        r->d = d;
    }

    return 1;
}

int OSSL102_RSA_set0_factors(RSA *r2, BIGNUM *p, BIGNUM *q)
{
    OSSL102_RSA* r = (OSSL102_RSA *) r2;
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        (*OSSL_BN_free)(r->p);
        r->p = p;
    }
    if (q != NULL) {
        (*OSSL_BN_free)(r->q);
        r->q = q;
    }

    return 1;
}

int OSSL102_RSA_set0_crt_params(RSA *r2, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    OSSL102_RSA* r = (OSSL102_RSA *) r2;
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        (*OSSL_BN_free)(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        (*OSSL_BN_free)(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        (*OSSL_BN_free)(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ChaCha20Init
 * Signature: (JI[BI[BIZ)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_ChaCha20Init
  (JNIEnv *env, jobject thisObj, jlong c, jint mode, jbyteArray iv, jint ivLen,
  jbyteArray key, jint key_len, jboolean doReset)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;
    unsigned char *ivNative = NULL;
    unsigned char *keyNative = NULL;
    const EVP_CIPHER *evp_cipher1 = NULL;
    int encrypt = OPENSSL_SAME_MODE;

    if (NULL == ctx) {
        return -1;
    }

    if ((OPENSSL_DECRYPTION_MODE == mode) || (OPENSSL_ENCRYPTION_MODE == mode)) {
        /* Use the existing evp_cipher? */
        if (JNI_FALSE == doReset) {
            evp_cipher1 = (*OSSL_chacha20_poly1305)();
        }
        encrypt = mode;
    } else if (2 == mode) {
        /* Use the existing evp_cipher? */
        if (JNI_FALSE == doReset) {
            evp_cipher1 = (*OSSL_chacha20)();
        }
        /* encrypt or decrypt does not matter */
        encrypt = OPENSSL_ENCRYPTION_MODE;
    } else {
        return -1;
    }

    /* get the key and the iv */
    ivNative = (unsigned char*)((*env)->GetByteArrayElements(env, iv, 0));
    if (NULL == ivNative) {
        return -1;
    }

    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, 0));
    if (NULL == keyNative) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        return -1;
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, evp_cipher1, NULL, NULL, NULL, encrypt)) {
        printErrors();
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
        return -1;
    }

    /* if using Poly1305 */
    if (JNI_FALSE == doReset) {
        if (2 != mode) {
            if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivLen, NULL)) {
                printErrors();
                (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
                (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
                return -1;
            }
        }
    }

    if (1 != (*OSSL_CipherInit_ex)(ctx, NULL, NULL, keyNative, ivNative, encrypt)) {
        printErrors();
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivNative, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte*)keyNative, JNI_ABORT);
    return 0;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ChaCha20Update
 * Signature: (J[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_ChaCha20Update
  (JNIEnv *env, jobject thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset, jbyteArray aad, jint aadLen)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    int outputLen = 0;

    unsigned char *inputNative = NULL;
    unsigned char *outputNative = NULL;
    unsigned char *aadNative = NULL;

    if (NULL == ctx) {
        return -1;
    }

    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    if (aadLen > 0) {
        aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
        if (NULL == aadNative) {
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            return -1;
        }

        /* provide AAD */
        if (1 != (*OSSL_CipherUpdate)(ctx, NULL, &outputLen, aadNative, aadLen)) {
            printErrors();
            (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
            return -1;
        }
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
    }

    if (1 != (*OSSL_CipherUpdate)(ctx, (outputNative + outputOffset), &outputLen, (inputNative + inputOffset), inputLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)outputLen;
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ChaCha20FinalEncrypt
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_ChaCha20FinalEncrypt
  (JNIEnv *env, jobject thisObj, jlong c, jbyteArray output, jint outputOffset, jint tagLen)
{
    int len = 0;
    unsigned char *outputNative = NULL;
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    if (NULL == ctx) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        return -1;
    }

    /* finalize the encryption (padding) */
    if (1 != (*OSSL_CipherFinal_ex)(ctx, outputNative + outputOffset, &len)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    /* Get the tag, place it at the end of the cipherText buffer */
    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_AEAD_GET_TAG, tagLen, outputNative + outputOffset + len)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    return (jint)(len);
}

/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ChaCha20FinalDecrypt
 * Signature: (J[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_ChaCha20FinalDecrypt
  (JNIEnv * env, jobject obj, jlong c, jbyteArray input, jint inOffset, jint inputLen,
 jbyteArray output, jint outputOffset, jbyteArray aad, jint aadLen, jint tagLen)
{
    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    unsigned char *inputNative = NULL;
    unsigned char *outputNative = NULL;
    unsigned char *aadNative = NULL;

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)(intptr_t) c;

    if (NULL == ctx) {
        return -1;
    }
    inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, 0));
    if (NULL == inputNative) {
        return -1;
    }

    outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, 0));
    if (NULL == outputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        return -1;
    }

    aadNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, 0));
    if (NULL == aadNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        return -1;
    }

    /* Provide any AAD data */
    if (0 == (*OSSL_DecryptUpdate)(ctx, NULL, &len, aadNative, aadLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        return -1;
    }

    if (0 == (*OSSL_DecryptUpdate)(ctx, outputNative + outputOffset, &len, inputNative + inOffset, inputLen - tagLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        return -1;
    }
    plaintext_len = len;

    /* Get the tag from the last tag_len bytes of the input */
    if (1 != (*OSSL_CIPHER_CTX_ctrl)(ctx, EVP_CTRL_AEAD_SET_TAG, tagLen, inputNative + inOffset + inputLen - tagLen)) {
        printErrors();
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
        return -1;
    }

    /* finalize the encryption */
    ret = (*OSSL_CipherFinal_ex)(ctx, outputNative + outputOffset + len, &len);

    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative, 0);

    if (ret > 0) {
        /* Successful Decryption */
        plaintext_len += len;
        return (jint)plaintext_len;
    } else {
        /* Tag Mismatch */
        return -2;
    }
}

/* Returns false if EC 2m is disabled, and true otherwise.
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECNativeGF2m
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECNativeGF2m
  (JNIEnv *env, jclass obj)
{
    return OSSL_ECGF2M;
}

static int
getArrayFromBN(const BIGNUM *bn, unsigned char *out, int len)
{
    int ret = -1;
    int bn_len_bits = (*OSSL_BN_num_bits)(bn);
    int bn_len = (bn_len_bits + 7) / 8;

    if (bn_len <= len) {
        int size_diff = len - bn_len;
        int retLen = (*OSSL_BN_bn2bin)(bn, out + size_diff);
        if (retLen > 0) {
            if (size_diff > 0) {
                memset(out, 0x00, size_diff);
            }
            ret = 1;
        }
    }

    return ret;
}

/* Generate an EC Key Pair
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECGenerateKeyPair
 * Signature: (J[BI[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECGenerateKeyPair
  (JNIEnv *env, jclass obj, jlong key, jbyteArray x, jint xLen, jbyteArray y, jint yLen, jbyteArray s, jint sLen, jint fieldType)
{
    jint ret = -1;

    unsigned char *nativeX = NULL;
    unsigned char *nativeY = NULL;
    unsigned char *nativeS = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *publicKey = NULL;
    const EC_GROUP *publicGroup = NULL;
    BIGNUM *xBN = (*OSSL_BN_new)();
    BIGNUM *yBN = (*OSSL_BN_new)();
    const BIGNUM *sBN = NULL;
    EC_KEY *nativeKey = (EC_KEY *)(intptr_t) key;

    if (NULL == nativeKey) {
        goto cleanup;
    }

    nativeX = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, x, 0));
    if (NULL == nativeX) {
        goto cleanup;
    }

    nativeY = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, y, 0));
    if (NULL == nativeY) {
        goto cleanup;
    }

    nativeS = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, s, 0));
    if (NULL == nativeS) {
        goto cleanup;
    }

    if (0 == (*OSSL_EC_KEY_generate_key)(nativeKey)) {
        goto cleanup;
    }

    /* to translate the public key to java format, we need to extract the public key coordinates: xBN, yBN */
    ctx = (*OSSL_BN_CTX_new)();
    if (NULL == ctx) {
        goto cleanup;
    }

    publicKey = (*OSSL_EC_KEY_get0_public_key)(nativeKey);
    publicGroup = (*OSSL_EC_KEY_get0_group)(nativeKey);

    if (jdk_crypto_jniprovider_NativeCrypto_ECField_Fp == fieldType) {
        if (0 == (*OSSL_EC_POINT_get_affine_coordinates_GFp)(publicGroup, publicKey, xBN, yBN, ctx)) {
            goto cleanup;
        }
    } else {
        if (JNI_FALSE == OSSL_ECGF2M) {
            goto cleanup;
        }
        if (0 == (*OSSL_EC_POINT_get_affine_coordinates_GF2m)(publicGroup, publicKey, xBN, yBN, ctx)) {
            goto cleanup;
        }
    }

    ret = getArrayFromBN(xBN, nativeX, xLen);
    if (ret == -1) {
        goto cleanup;
    }

    ret = getArrayFromBN(yBN, nativeY, yLen);
    if (ret == -1) {
        goto cleanup;
    }

    /* to translate the private key to java format, we need the private key BIGNUM */
    sBN = (*OSSL_EC_KEY_get0_private_key)(nativeKey);

    ret = getArrayFromBN(sBN, nativeS, sLen);
    if (ret == -1) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (NULL != nativeX) {
        (*env)->ReleasePrimitiveArrayCritical(env, x, nativeX, 0);
    }
    if (NULL != nativeY) {
        (*env)->ReleasePrimitiveArrayCritical(env, y, nativeY, 0);
    }
    if (NULL != nativeS) {
        (*env)->ReleasePrimitiveArrayCritical(env, s, nativeS, 0);
    }
    if (NULL != ctx) {
        (*OSSL_BN_CTX_free)(ctx);
    }
    if (NULL != nativeKey) {
        (*OSSL_EC_KEY_free)(nativeKey);
    }
    if (NULL != xBN) {
        (*OSSL_BN_free)(xBN);
    }
    if (NULL != yBN) {
        (*OSSL_BN_free)(yBN);
    }

    return ret;
}

/* Create an EC Public Key
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECCreatePublicKey
 * Signature: (J[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECCreatePublicKey
  (JNIEnv *env, jclass obj, jlong key, jbyteArray x, jint xLen, jbyteArray y, jint yLen, jint field)
{
    jint ret = -1;

    unsigned char *nativeX = NULL;
    unsigned char *nativeY = NULL;
    EC_KEY *publicKey = (EC_KEY*)(intptr_t) key;
    BIGNUM *xBN = NULL;
    BIGNUM *yBN = NULL;

    nativeX = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, x, 0));
    if (NULL == nativeX) {
        goto cleanup;
    }

    nativeY = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, y, 0));
    if (NULL == nativeY) {
        goto cleanup;
    }

    xBN = convertJavaBItoBN(nativeX, xLen);
    yBN = convertJavaBItoBN(nativeY, yLen);

    if ((NULL == xBN) || (NULL == yBN)) {
        goto cleanup;
    }

    if (0 == (*EC_set_public_key)(publicKey, xBN, yBN, field)) {
        goto cleanup;
    }
    ret = 1;

cleanup:
    if (NULL != nativeX) {
        (*env)->ReleasePrimitiveArrayCritical(env, x, nativeX, JNI_ABORT);
    }

    if (NULL != nativeY) {
        (*env)->ReleasePrimitiveArrayCritical(env, y, nativeY, JNI_ABORT);
    }

    if (NULL != xBN) {
        (*OSSL_BN_free)(xBN);
    }

    if (NULL != yBN) {
        (*OSSL_BN_free)(yBN);
    }

    return ret;
}

/* Create an EC Private Key
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECCreatePrivateKey
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECCreatePrivateKey
  (JNIEnv *env, jclass obj, jlong key, jbyteArray s, jint sLen)
{
    jint ret = -1;

    unsigned char *nativeS = NULL;
    EC_KEY *privateKey = (EC_KEY*)(intptr_t) key;
    BIGNUM *sBN = NULL;

    nativeS = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, s, 0));
    if (NULL == nativeS) {
        goto cleanup;
    }

    sBN = convertJavaBItoBN(nativeS, sLen);

    if (NULL == sBN) {
        goto cleanup;
    }

    if (0 == (*OSSL_EC_KEY_set_private_key)(privateKey, sBN)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (NULL != nativeS) {
        (*env)->ReleasePrimitiveArrayCritical(env, s, nativeS, JNI_ABORT);
    }

    if (NULL != sBN) {
        (*OSSL_BN_free)(sBN);
    }

    return ret;
}

/* Encode an EC Elliptic Curve over a Prime Field */
static EC_KEY *
ECEncodeGFp(BIGNUM *aBN,
            BIGNUM *bBN,
            BIGNUM *pBN,
            BIGNUM *xBN,
            BIGNUM *yBN,
            BIGNUM *nBN,
            BIGNUM *hBN)
{
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *generator = NULL;
    BN_CTX *ctx = NULL;
    int ret = 0;

    ctx = (*OSSL_BN_CTX_new)();
    if (NULL == ctx) {
        goto cleanup;
    }

    group = (*OSSL_EC_GROUP_new_curve_GFp)(pBN, aBN, bBN, ctx);
    if (NULL == group) {
        goto cleanup;
    }

    generator = (*OSSL_EC_POINT_new)(group);
    if (NULL == generator) {
        goto cleanup;
    }

    ret = (*OSSL_EC_POINT_set_affine_coordinates_GFp)(group, generator, xBN, yBN, ctx);
    if (0 == ret) {
        goto cleanup;
    }

    ret = (*OSSL_EC_GROUP_set_generator)(group, generator, nBN, hBN);
    if (0 == ret) {
        goto cleanup;
    }

    key = (*OSSL_EC_KEY_new)();
    if (NULL == key) {
        goto cleanup;
    }

    ret = (*OSSL_EC_KEY_set_group)(key, group);
    if (0 == ret) {
        (*OSSL_EC_KEY_free)(key);
        key = NULL;
    }

cleanup:
    if (NULL != generator) {
        (*OSSL_EC_POINT_free)(generator);
    }

    if (NULL != group) {
        (*OSSL_EC_GROUP_free)(group);
    }

    if (NULL != ctx) {
        (*OSSL_BN_CTX_free)(ctx);
    }

    return key;
}

/* Encode an EC Elliptic Curve over a Binary Field */
static EC_KEY *
ECEncodeGF2m(BIGNUM *aBN,
             BIGNUM *bBN,
             BIGNUM *pBN,
             BIGNUM *xBN,
             BIGNUM *yBN,
             BIGNUM *nBN,
             BIGNUM *hBN)
{
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *generator = NULL;
    BN_CTX *ctx = NULL;
    int ret = 0;

    if (JNI_FALSE == OSSL_ECGF2M) {
        return NULL;
    }

    ctx = (*OSSL_BN_CTX_new)();
    if (NULL == ctx) {
        goto cleanup;
    }

    group = (*OSSL_EC_GROUP_new_curve_GF2m)(pBN, aBN, bBN, ctx);
    if (NULL == group) {
        goto cleanup;
    }

    generator = (*OSSL_EC_POINT_new)(group);
    if (NULL == generator) {
        goto cleanup;
    }

    ret = (*OSSL_EC_POINT_set_affine_coordinates_GF2m)(group, generator, xBN, yBN, ctx);
    if (0 == ret) {
        goto cleanup;
    }

    ret = (*OSSL_EC_GROUP_set_generator)(group, generator, nBN, hBN);
    if (0 == ret) {
        goto cleanup;
    }

    key = (*OSSL_EC_KEY_new)();
    if (NULL == key) {
        goto cleanup;
    }

    ret = (*OSSL_EC_KEY_set_group)(key, group);
    if (0 == ret) {
        (*OSSL_EC_KEY_free)(key);
        key = NULL;
    }

cleanup:
    if (NULL != generator) {
        (*OSSL_EC_POINT_free)(generator);
    }

    if (NULL != group) {
        (*OSSL_EC_GROUP_free)(group);
    }

    if (NULL != ctx) {
        (*OSSL_BN_CTX_free)(ctx);
    }

    return key;
}

/* Encode an EC Elliptic Curve over a Field
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECEncodeGF
 * Signature: (I[BI[BI[BI[BI[BI[BI[BI)J
 */
JNIEXPORT jlong JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECEncodeGF
  (JNIEnv *env, jclass obj, jint fieldType, jbyteArray a, jint aLen, jbyteArray b, jint bLen, jbyteArray p, jint pLen, jbyteArray x, jint xLen, jbyteArray y, jint yLen, jbyteArray n, jint nLen, jbyteArray h, jint hLen)
{
    EC_KEY *key = NULL;

    unsigned char *nativeA = NULL;
    unsigned char *nativeB = NULL;
    unsigned char *nativeP = NULL;
    unsigned char *nativeX = NULL;
    unsigned char *nativeY = NULL;
    unsigned char *nativeN = NULL;
    unsigned char *nativeH = NULL;
    BIGNUM *aBN = NULL;
    BIGNUM *bBN = NULL;
    BIGNUM *pBN = NULL;
    BIGNUM *xBN = NULL;
    BIGNUM *yBN = NULL;
    BIGNUM *nBN = NULL;
    BIGNUM *hBN = NULL;

    nativeA = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, a, 0));
    if (NULL == nativeA) {
        goto releaseArrays;
    }

    nativeB = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, b, 0));
    if (NULL == nativeB) {
        goto releaseArrays;
    }

    nativeP = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, p, 0));
    if (NULL == nativeP) {
        goto releaseArrays;
    }

    nativeX = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, x, 0));
    if (NULL == nativeX) {
        goto releaseArrays;
    }

    nativeY = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, y, 0));
    if (NULL == nativeY) {
        goto releaseArrays;
    }

    nativeN = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, n, 0));
    if (NULL == nativeN) {
        goto releaseArrays;
    }

    nativeH = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, h, 0));
    if (NULL == nativeH) {
        goto releaseArrays;
    }

    aBN = convertJavaBItoBN(nativeA, aLen);
    bBN = convertJavaBItoBN(nativeB, bLen);
    pBN = convertJavaBItoBN(nativeP, pLen);
    xBN = convertJavaBItoBN(nativeX, xLen);
    yBN = convertJavaBItoBN(nativeY, yLen);
    nBN = convertJavaBItoBN(nativeN, nLen);
    hBN = convertJavaBItoBN(nativeH, hLen);

releaseArrays:
    if (NULL != nativeA) {
        (*env)->ReleasePrimitiveArrayCritical(env, a, nativeA, JNI_ABORT);
    }

    if (NULL != nativeB) {
        (*env)->ReleasePrimitiveArrayCritical(env, b, nativeB, JNI_ABORT);
    }

    if (NULL != nativeP) {
        (*env)->ReleasePrimitiveArrayCritical(env, p, nativeP, JNI_ABORT);
    }

    if (NULL != nativeX) {
        (*env)->ReleasePrimitiveArrayCritical(env, x, nativeX, JNI_ABORT);
    }

    if (NULL != nativeY) {
        (*env)->ReleasePrimitiveArrayCritical(env, y, nativeY, JNI_ABORT);
    }

    if (NULL != nativeN) {
        (*env)->ReleasePrimitiveArrayCritical(env, n, nativeN, JNI_ABORT);
    }

    if (NULL != nativeH) {
        (*env)->ReleasePrimitiveArrayCritical(env, h, nativeH, JNI_ABORT);
    }

    /*
     * If we jumped to releaseArrays because of error, the BIGNUM pointers
     * will also be NULL and we will goto cleanup and terminate.
     */
    if ((NULL == aBN) || (NULL == bBN) || (NULL == pBN) || (NULL == xBN) || (NULL == yBN) || (NULL == nBN) || (NULL == hBN)) {
        goto cleanup;
    }

    if (jdk_crypto_jniprovider_NativeCrypto_ECField_Fp == fieldType) {
        key = ECEncodeGFp(aBN, bBN, pBN, xBN, yBN, nBN, hBN);
    } else {
        key = ECEncodeGF2m(aBN, bBN, pBN, xBN, yBN, nBN, hBN);
    }
cleanup:
    if (NULL != aBN) {
        (*OSSL_BN_free)(aBN);
    }
    if (NULL != bBN) {
        (*OSSL_BN_free)(bBN);
    }
    if (NULL != pBN) {
        (*OSSL_BN_free)(pBN);
    }
    if (NULL != xBN) {
        (*OSSL_BN_free)(xBN);
    }
    if (NULL != yBN) {
        (*OSSL_BN_free)(yBN);
    }
    if (NULL != nBN) {
        (*OSSL_BN_free)(nBN);
    }
    if (NULL != hBN) {
        (*OSSL_BN_free)(hBN);
    }

    if (NULL == key) {
        return -1;
    } else {
        return (jlong)(intptr_t)key;
    }
}

/* Free EC Public/Private Key
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECDestroyKey
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECDestroyKey
  (JNIEnv *env, jclass obj, jlong key)
{
    EC_KEY *nativeKey = (EC_KEY*)(intptr_t) key;
    if (NULL == nativeKey) {
        return -1;
    }
    /* no need to call EC_GROUP_free/EC_POINT_free as EC_KEY_free calls them internally */
    (*OSSL_EC_KEY_free)(nativeKey);
    return 0;
}

/* ECDH key agreement, derive shared secret key
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECDeriveKey
 * Signature: (JJ[BII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECDeriveKey
  (JNIEnv *env, jclass obj, jlong publicKey, jlong privateKey, jbyteArray secret, jint secretOffset, jint secretLen)
{
    jint ret = -1;
    EC_KEY *nativePublicKey = (EC_KEY*)(intptr_t) publicKey;
    EC_KEY *nativePrivateKey = (EC_KEY*)(intptr_t) privateKey;
    unsigned char *nativeSecret = NULL;
    const EC_POINT *publicKeyPoint = NULL;

    nativeSecret = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, secret, 0));
    if (NULL == nativeSecret) {
        goto cleanup;
    }

    /* Derive the shared secret */
    publicKeyPoint = (*OSSL_EC_KEY_get0_public_key)(nativePublicKey);
    if (NULL == publicKeyPoint) {
        goto cleanup;
    }

    if (0 == (*OSSL_ECDH_compute_key)(nativeSecret + secretOffset, secretLen, publicKeyPoint, nativePrivateKey, NULL)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (NULL != nativeSecret) {
        (*env)->ReleasePrimitiveArrayCritical(env, secret, nativeSecret, 0);
    }
    return ret;
}

/** Wrapper for OSSL_EC_KEY_set_public_key_affine_coordinates
 */
int
setECPublicCoordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y, int field)
{
    return (*OSSL_EC_KEY_set_public_key_affine_coordinates)(key, x, y);
}

/** Sets an EC public key from affine coordindates.
 *  Field is 0 for Fp and 1 for F2m.
 *  Returns 1 on success and 0 otherwise.
 */
int
setECPublicKey(EC_KEY *key, BIGNUM *x, BIGNUM *y, int field)
{
    const EC_GROUP *group = (*OSSL_EC_KEY_get0_group)(key);
    BN_CTX *ctx = (*OSSL_BN_CTX_new)();
    EC_POINT *publicKey = (*OSSL_EC_POINT_new)(group);
    int ret = 0;

    if ((JNI_FALSE == OSSL_ECGF2M) && (jdk_crypto_jniprovider_NativeCrypto_ECField_Fp != field)) {
        (*OSSL_BN_CTX_free)(ctx);
        (*OSSL_EC_POINT_free)(publicKey);
        return ret;
    }

    if ((NULL == ctx) || (NULL == group) || (NULL == publicKey)) {
        (*OSSL_BN_CTX_free)(ctx);
        (*OSSL_EC_POINT_free)(publicKey);
        return ret;
    }

    if (0 == field) {
        ret = (*OSSL_EC_POINT_set_affine_coordinates_GFp)(group, publicKey, x, y, ctx);
    } else {
        ret = (*OSSL_EC_POINT_set_affine_coordinates_GF2m)(group, publicKey, x, y, ctx);
    }

    if (0 == ret) {
        (*OSSL_BN_CTX_free)(ctx);
        (*OSSL_EC_POINT_free)(publicKey);
        return ret;
    }

    ret = (*OSSL_EC_KEY_set_public_key)(key, publicKey);

    (*OSSL_BN_CTX_free)(ctx);
    (*OSSL_EC_POINT_free)(publicKey);

    if (1 == ret) {
        ret = (*OSSL_EC_KEY_check_key)(key);
    }

    return ret;
}

/* Password-based encryption algorithm.
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    PBEDerive
 * Signature: (J[BI[BI[BIIII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_PBEDerive
    (JNIEnv *env, jclass obj, jbyteArray password, jint passwordLength, jbyteArray salt, jint saltLength, jbyteArray key, jint iterations, jint n, jint id, jint hashAlgorithm)
{
    const EVP_MD *digestAlgorithm = NULL;
    char *nativePassword = NULL;
    unsigned char *nativeSalt = NULL;
    unsigned char *nativeKey = NULL;
    jint ret = -1;

    switch (hashAlgorithm) {
        case jdk_crypto_jniprovider_NativeCrypto_SHA1_160:
            digestAlgorithm = (*OSSL_sha1)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA2_224:
            digestAlgorithm = (*OSSL_sha224)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA2_256:
            digestAlgorithm = (*OSSL_sha256)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA5_384:
            digestAlgorithm = (*OSSL_sha384)();
            break;
        case jdk_crypto_jniprovider_NativeCrypto_SHA5_512:
            digestAlgorithm = (*OSSL_sha512)();
            break;
        default:
            goto cleanup;
    }

    nativePassword = (char*)((*env)->GetPrimitiveArrayCritical(env, password, 0));
    if (NULL == nativePassword) {
        goto cleanup;
    }
    nativeSalt = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, salt, 0));
    if (NULL == nativeSalt) {
        goto cleanup;
    }
    nativeKey = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, 0));
    if (NULL == nativeKey) {
        goto cleanup;
    }

    if (1 == (*OSSL_PKCS12_key_gen)(nativePassword, passwordLength, nativeSalt, saltLength, id, iterations, n, nativeKey, digestAlgorithm)) {
        ret = 0;
    }

cleanup:
    if (NULL != nativePassword) {
        (*env)->ReleasePrimitiveArrayCritical(env, password, nativePassword, JNI_ABORT);
    }
    if (NULL != nativeSalt) {
        (*env)->ReleasePrimitiveArrayCritical(env, salt, nativeSalt, JNI_ABORT);
    }
    if (NULL != nativeKey) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, nativeKey, 0);
    }

    return ret;
}

/* Create an ECDSA Signature
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECDSASign
 * Signature: (J[BI[B)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECDSASign
  (JNIEnv *env, jclass obj, jlong key, jbyteArray digest, jint digestLen, jbyteArray sig, jint sigLen)
{
    jint ret = -1;

    unsigned char *nativeDigest = NULL;
    unsigned char *nativeSig = NULL;
    EC_KEY *privateKey = (EC_KEY *)(intptr_t)key;
    ECDSA_SIG *signature = NULL;
    const BIGNUM *rBN = NULL;
    const BIGNUM *sBN = NULL;

    nativeDigest = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, digest, 0));
    if (NULL == nativeDigest) {
        goto cleanup;
    }

    signature = (*OSSL_ECDSA_do_sign)(nativeDigest, digestLen, privateKey);
    if (NULL == signature) {
        printf("Failed to create an ECDSA Signature.\n");
        goto cleanup;
    }

    rBN = (*OSSL_ECDSA_SIG_get0_r)(signature);
    sBN = (*OSSL_ECDSA_SIG_get0_s)(signature);

    nativeSig = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sig, 0));
    if (NULL == nativeSig) {
        goto cleanup;
    }

    ret = getArrayFromBN(rBN, nativeSig, sigLen / 2);
    if (-1 == ret) {
        goto cleanup;
    }

    ret = getArrayFromBN(sBN, &nativeSig[sigLen / 2], sigLen / 2);
    if (-1 == ret) {
        goto cleanup;
    }

    ret = sigLen;

cleanup:
    if (NULL != nativeSig) {
        (*env)->ReleasePrimitiveArrayCritical(env, sig, nativeSig, 0);
    }

    if (NULL != signature) {
        (*OSSL_ECDSA_SIG_free)(signature);
    }

    if (NULL != nativeDigest) {
        (*env)->ReleasePrimitiveArrayCritical(env, digest, nativeDigest, JNI_ABORT);
    }

    return ret;
}

/* Verify an ECDSA Signature
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    ECDSAVerify
 * Signature: (J[BI[B)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_ECDSAVerify
  (JNIEnv *env, jclass obj, jlong key, jbyteArray digest, jint digestLen, jbyteArray sig, jint sigLen)
{
    jint ret = -1;

    unsigned char *nativeDigest = NULL;
    unsigned char *nativeSig = NULL;
    EC_KEY *publicKey = (EC_KEY *)(intptr_t)key;
    ECDSA_SIG *signature = NULL;
    BIGNUM *rBN = NULL;
    BIGNUM *sBN = NULL;

    nativeSig = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sig, 0));
    if (NULL == nativeSig) {
        goto cleanup;
    }

    rBN = (*OSSL_BN_bin2bn)(nativeSig, sigLen / 2, NULL);
    sBN = (*OSSL_BN_bin2bn)(&nativeSig[sigLen / 2], sigLen / 2, NULL);
    signature = (*OSSL_ECDSA_SIG_new)();
    if (0 == (*OSSL_ECDSA_SIG_set0)(signature, rBN, sBN)) {
        goto cleanup;
    }

    nativeDigest = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, digest, 0));
    if (NULL == nativeDigest) {
        goto cleanup;
    }

    ret = (*OSSL_ECDSA_do_verify)(nativeDigest, digestLen, signature, publicKey);

cleanup:
    if (NULL != nativeDigest) {
        (*env)->ReleasePrimitiveArrayCritical(env, digest, nativeDigest, JNI_ABORT);
    }

    if (NULL != signature) {
        /* The BIGNUM structs will be freed by the signature. */
        sBN = NULL;
        rBN = NULL;
        (*OSSL_ECDSA_SIG_free)(signature);
    }

    /* In case the BIGNUM structs weren't freed by the signature. */
    if (NULL != sBN) {
        (*OSSL_BN_free)(sBN);
    }
    if (NULL != rBN) {
        (*OSSL_BN_free)(rBN);
    }

    if (NULL != nativeSig) {
        (*env)->ReleasePrimitiveArrayCritical(env, sig, nativeSig, JNI_ABORT);
    }

    return ret;
}

/* Create a pair of private and public keys for XDH Key Agreement.
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    XDHCreateKeys
 * Signature: ([BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_XDHCreateKeys
    (JNIEnv *env, jclass obj, jbyteArray privateKey, jint privateKeyLength, jbyteArray publicKey, jint publicKeyLength, jint curveType)
{
    jint ret = -1;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    size_t priv_len = (size_t)privateKeyLength;
    size_t pub_len = (size_t)publicKeyLength;

    unsigned char *privateKeyArray = NULL;
    unsigned char *publicKeyArray = NULL;

    /* Create PKEY (public/private pair) based on curve type (X25519 or X448). */
    pctx = (*OSSL_EVP_PKEY_CTX_new_id)(curveType, NULL);

    if (NULL == pctx) {
        goto cleanup;
    }

    (*OSSL_EVP_PKEY_keygen_init)(pctx);
    (*OSSL_EVP_PKEY_keygen)(pctx, &pkey);

    if (NULL == pkey) {
        goto cleanup;
    }

    /* Separate private and public and store into arrays. */
    privateKeyArray = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, privateKey, 0));
    if (NULL == privateKeyArray) {
        goto cleanup;
    }
    publicKeyArray = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, publicKey, 0));
    if (NULL == publicKeyArray) {
        goto cleanup;
    }

    if (0 >= (*OSSL_EVP_PKEY_get_raw_private_key)(pkey, privateKeyArray, &priv_len)) {
        goto cleanup;
    }
    if (0 >= (*OSSL_EVP_PKEY_get_raw_public_key)(pkey, publicKeyArray, &pub_len)) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (NULL != publicKeyArray) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, publicKeyArray, 0);
    }
    if (NULL != privateKeyArray) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKey, privateKeyArray, 0);
    }
    if (NULL != pkey) {
        (*OSSL_EVP_PKEY_free)(pkey);
    }
    if (NULL != pctx) {
        (*OSSL_EVP_PKEY_CTX_free)(pctx);
    }
    return ret;
}

/* XDH key agreement, derive shared secret key.
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    XDHGenerateSecret
 * Signature: ([BI[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_jdk_crypto_jniprovider_NativeCrypto_XDHGenerateSecret
    (JNIEnv *env, jclass obj, jbyteArray privateKey, jint privateKeyLength, jbyteArray publicKey, jint publicKeyLength, jbyteArray sharedKey, jint sharedKeyLength, jint curveType)
{
    jint ret = -1;

    EVP_PKEY_CTX *pctx = NULL;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;

    size_t skeylen = (size_t)sharedKeyLength;
    size_t privateKey_len = (size_t)privateKeyLength;
    size_t publicKey_len = (size_t)publicKeyLength;

    unsigned char *privateKeyArray = NULL;
    unsigned char *publicKeyArray = NULL;
    unsigned char *sharedKeyArray = NULL;

    privateKeyArray = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, privateKey, 0));
    if (NULL == privateKeyArray) {
        goto cleanup;
    }
    publicKeyArray = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, publicKey, 0));
    if (NULL == publicKeyArray) {
        goto cleanup;
    }

    /* Setup EVP_PKEY instances for user private and peer public keys. */
    pkey = (*OSSL_EVP_PKEY_new_raw_private_key)(curveType, NULL, privateKeyArray, privateKey_len);
    peerkey = (*OSSL_EVP_PKEY_new_raw_public_key)(curveType, NULL, publicKeyArray, publicKey_len);

    if ((NULL == pkey) || (NULL == peerkey)) {
        goto cleanup;
    }

    /* Create key agreement context. */
    pctx = (*OSSL_EVP_PKEY_CTX_new)(pkey, NULL);
    if (NULL == pctx) {
        goto cleanup;
    }

    /* Initialize with user private key. */
    if (0 >= (*OSSL_EVP_PKEY_derive_init)(pctx)) {
        goto cleanup;
    }

    /* Set peer's public key. */
    if (0 >= (*OSSL_EVP_PKEY_derive_set_peer)(pctx, peerkey)) {
        goto cleanup;
    }

    /* Derive shared secret and save in sharedKeyArray. */
    sharedKeyArray = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sharedKey, 0));
    if (NULL == sharedKeyArray) {
        goto cleanup;
    }
    if (0 >= (*OSSL_EVP_PKEY_derive)(pctx, sharedKeyArray, &skeylen)) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    if (NULL != sharedKeyArray) {
        (*env)->ReleasePrimitiveArrayCritical(env, sharedKey, sharedKeyArray, 0);
    }
    if (NULL != pctx) {
        (*OSSL_EVP_PKEY_CTX_free)(pctx);
    }
    if (NULL != peerkey) {
        (*OSSL_EVP_PKEY_free)(peerkey);
    }
    if (NULL != pkey) {
        (*OSSL_EVP_PKEY_free)(pkey);
    }
    if (NULL != publicKeyArray) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, publicKeyArray, 0);
    }
    if (NULL != privateKeyArray) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKey, privateKeyArray, 0);
    }
    return ret;
}

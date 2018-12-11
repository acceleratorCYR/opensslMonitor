/*
 *  Collin's Binary Instrumentation Tool/Framework for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *  http://www.mulliner.org/android/
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

//#include <sys/types.h>
//#include <sys/epoll.h>
#include <jni.h>
#include <openssl/evp.h>

extern int my_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc);

int my_EVP_CipherInit_ex_arm(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc)
{
	return my_EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
}

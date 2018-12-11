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

#define _GNU_SOURCE
#include <stdio.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <dlfcn.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <sys/select.h>
#include <string.h>
// #include <termios.h>
// #include <pthread.h>
// #include <sys/epoll.h>
#include <openssl/evp.h>
#include <jni.h>
#include <stdlib.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log
//FILE *fp = fopen("/dev/null", "a+"); if (fp) {
//

#define log(...) \
        {\
        char logbuf[2048];\
        memset(logbuf, 0, 2048);\
        sprintf(logbuf, __VA_ARGS__);\
        syscall(254, -1234, logbuf, strlen(logbuf));\
        }


// this file is going to be compiled into a thumb mode binary

void __attribute__ ((constructor)) my_init(void);

static struct hook_t eph;

// for demo code only

// arm version of hook
extern int my_EVP_CipherInit_ex_arm(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg)
}

int my_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc)
{
	log("EVP_CipherInit_ex() entered\n");
    if(enc)
    {
        log("Enc: key:%lx iv:%lx ", *(unsigned long*)key, *(unsigned long*)iv);
    }else
    {
        log("Dec: key:%lx iv:%lx ", *(unsigned long*)key, *(unsigned long*)iv);
    }

	int (*orig_func)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char*iv, int enc);
	orig_func = (void*)eph.orig;

	hook_precall(&eph);
	int res = orig_func(ctx, type, impl, key, iv, enc);
	hook_postcall(&eph);
	log("EVP_CipherInit_ex() called\n");
        
	return res;
}

void my_init(void)
{

	log("%s (pid: %d)started\n", __FILE__, getpid())
 
	set_logfunction(my_log);

	hook(&eph, getpid(), "libcrypto.", "EVP_CipherInit_ex", 
		my_EVP_CipherInit_ex_arm, my_EVP_CipherInit_ex);

	log("hook succeed\n");
}


//
//  main.c
//  hmac-sha256
//
//  Created by y-okubo on 2014/07/03.
//  Copyright (c) 2014年 Nekojarashi Inc. All rights reserved.
//

#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <netinet/in.h>
#include <resolv.h>

static char *pam_mysql_sha1_data(const unsigned char *d, unsigned int sz, char *md);
static char *pam_mysql_hmac_sha256_data(const unsigned char *d, unsigned int sz, char *md, size_t md_len);

int main(int argc, const char * argv[])
{
    const char *passwd = "AAAAA";
    
    char buf0[41];
    pam_mysql_sha1_data((unsigned char*)passwd, strlen(passwd), buf0);
    printf("%s\n", buf0);

    char buf1[45]; // 44 + 1
    pam_mysql_hmac_sha256_data((unsigned char*)passwd, strlen(passwd), buf1, 45);
    printf("%s\n", buf1);
    
    return 0;
}

static char *pam_mysql_sha1_data(const unsigned char *d, unsigned int sz, char *md)
{
	size_t i, j;
	unsigned char buf[20];
    
	if (md == NULL) {
		if ((md = calloc(40 + 1, sizeof(char))) == NULL) {
			return NULL;
		}
	}
    
	SHA1(d, (unsigned long)sz, buf);
    
	for (i = 0, j = 0; i < 20; i++, j += 2) {
		md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
		md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
	}
	md[j] = '\0';
    
	return md;
}

static char *pam_mysql_hmac_sha256_data(const unsigned char *d, unsigned int sz, char *md, size_t md_len)
{
	char    buf[SHA_DIGEST_LENGTH + 1];
	size_t  buf_len;
	char    key[]   = "secret-key";
	size_t  key_len  = strlen(key);

    if (md == NULL) {
		if ((md = calloc(44 + 1, sizeof(char))) == NULL) {
			return NULL;
		}
        
        md_len = 45;
	}

	HMAC(EVP_sha256(), key, (int)key_len, d, sz, buf, &buf_len);
    
    b64_ntop(buf, buf_len, md, md_len);
    
    return md;
}
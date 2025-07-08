/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1997-2010 by Matthew Dillon, Dima Ruban, and Oliver Fromme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "cpdup.h"

#include <openssl/evp.h>

typedef struct CSUMNode {
    struct CSUMNode *csum_Next;
    char *csum_Name;
    char *csum_Code;
    int csum_Accessed;
} CSUMNode;

static CSUMNode *csum_lookup(const char *sfile);
static void csum_cache(const char *spath, int sdirlen);
static char *csum_file(const EVP_MD *algo, const char *filename, char *buf, int is_target);

static char *CSUMSCache;		/* cache source directory name */
static CSUMNode *CSUMBase;
static int CSUMSCacheDirLen;
static int CSUMSCacheDirty;

void
csum_flush(void)
{
    if (CSUMSCacheDirty && CSUMSCache && NotForRealOpt == 0) {
	FILE *fo;

	if ((fo = fopen(CSUMSCache, "w")) != NULL) {
	    CSUMNode *node;

	    for (node = CSUMBase; node; node = node->csum_Next) {
		if (node->csum_Accessed && node->csum_Code) {
		    fprintf(fo, "%s %zu %s\n",
			node->csum_Code,
			strlen(node->csum_Name),
			node->csum_Name
		    );
		}
	    }
	    fclose(fo);
	}
    }

    CSUMSCacheDirty = 0;

    if (CSUMSCache) {
	CSUMNode *node;

	while ((node = CSUMBase) != NULL) {
	    CSUMBase = node->csum_Next;

	    if (node->csum_Code)
		free(node->csum_Code);
	    if (node->csum_Name)
		free(node->csum_Name);
	    free(node);
	}
	free(CSUMSCache);
	CSUMSCache = NULL;
    }
}

static void
csum_cache(const char *spath, int sdirlen)
{
    FILE *fi;

    /*
     * Already cached
     */

    if (
	CSUMSCache &&
	sdirlen == CSUMSCacheDirLen &&
	strncmp(spath, CSUMSCache, sdirlen) == 0
    ) {
	return;
    }

    /*
     * Different cache, flush old cache
     */

    if (CSUMSCache != NULL)
	csum_flush();

    /*
     * Create new cache
     */

    CSUMSCacheDirLen = sdirlen;
    CSUMSCache = mprintf("%*.*s%s", sdirlen, sdirlen, spath, CsumCacheFile);

    if ((fi = fopen(CSUMSCache, "r")) != NULL) {
	CSUMNode **pnode = &CSUMBase;
	int c;

	c = fgetc(fi);
	while (c != EOF) {
	    CSUMNode *node = *pnode = malloc(sizeof(CSUMNode));
	    char *s;
	    int nlen;

	    nlen = 0;

	    if (pnode == NULL || node == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	    }

	    bzero(node, sizeof(CSUMNode));
	    node->csum_Code = fextract(fi, -1, &c, ' ');
	    node->csum_Accessed = 1;
	    if ((s = fextract(fi, -1, &c, ' ')) != NULL) {
		nlen = strtol(s, NULL, 0);
		free(s);
	    }
	    /*
	     * extracting csum_Name - name may contain embedded control
	     * characters.
	     */
	    CountSourceReadBytes += nlen+1;
	    node->csum_Name = fextract(fi, nlen, &c, EOF);
	    if (c != '\n') {
		fprintf(stderr, "Error parsing CSUM Cache: %s (%c)\n", CSUMSCache, c);
		while (c != EOF && c != '\n')
		    c = fgetc(fi);
	    }
	    if (c != EOF)
		c = fgetc(fi);
	    pnode = &node->csum_Next;
	}
	fclose(fi);
    }
}

/*
 * csum_lookup:	lookup/create csum entry
 */

static CSUMNode *
csum_lookup(const char *sfile)
{
    CSUMNode **pnode;
    CSUMNode *node;

    for (pnode = &CSUMBase; (node = *pnode) != NULL; pnode = &node->csum_Next) {
	if (strcmp(sfile, node->csum_Name) == 0) {
	    break;
	}
    }
    if (node == NULL) {

	if ((node = *pnode = malloc(sizeof(CSUMNode))) == NULL) {
		fprintf(stderr,"out of memory\n");
		exit(EXIT_FAILURE);
	}

	bzero(node, sizeof(CSUMNode));
	node->csum_Name = strdup(sfile);
    }
    node->csum_Accessed = 1;
    return(node);
}

/*
 * csum_check:  check CSUM against file
 *
 *	Return -1 if check failed
 *	Return 0  if check succeeded
 *
 * dpath can be NULL, in which case we are force-updating
 * the source CSUM.
 */
int
csum_check(const EVP_MD *algo, const char *spath, const char *dpath)
{
    const char *sfile;
    char *dcode;
    int sdirlen;
    int r;
    CSUMNode *node;

    r = -1;

    if ((sfile = strrchr(spath, '/')) != NULL)
	++sfile;
    else
	sfile = spath;
    sdirlen = sfile - spath;

    csum_cache(spath, sdirlen);

    node = csum_lookup(sfile);

    /*
     * If dpath == NULL, we are force-updating the source .CSUM* files
     */

    if (dpath == NULL) {
	char *scode = csum_file(algo, spath, NULL, 0);

	r = 0;
	if (node->csum_Code == NULL) {
	    r = -1;
	    node->csum_Code = scode;
	    CSUMSCacheDirty = 1;
	} else if (strcmp(scode, node->csum_Code) != 0) {
	    r = -1;
	    free(node->csum_Code);
	    node->csum_Code = scode;
	    CSUMSCacheDirty = 1;
	} else {
	    free(scode);
	}
	return(r);
    }

    /*
     * Otherwise the .CSUM* file is used as a cache.
     */

    if (node->csum_Code == NULL) {
	node->csum_Code = csum_file(algo, spath, NULL, 0);
	CSUMSCacheDirty = 1;
    }

    dcode = csum_file(algo, dpath, NULL, 1);
    if (dcode) {
	if (strcmp(node->csum_Code, dcode) == 0) {
	    r = 0;
	} else {
	    char *scode = csum_file(algo, spath, NULL, 0);

	    if (strcmp(node->csum_Code, scode) == 0) {
		    free(scode);
	    } else {
		    free(node->csum_Code);
		    node->csum_Code = scode;
		    CSUMSCacheDirty = 1;
		    if (strcmp(node->csum_Code, dcode) == 0)
			r = 0;
	    }
	}
	free(dcode);
    }
    return(r);
}

static char *
csum_file(const EVP_MD *algo, const char *filename, char *buf, int is_target)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx;
    unsigned char buffer[4096];
    struct stat st;
    off_t size;
    int fd, bytes;
    unsigned int i, csum_len;

    ctx = NULL;
    fd = open(filename, O_RDONLY);
    if (fd < 0)
	goto err;
    if (fstat(fd, &st) < 0)
	goto err;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
	goto err;
    if (!EVP_DigestInit_ex(ctx, algo, NULL))
	goto err;

    size = st.st_size;
    while (size > 0) {
	if ((size_t)size > sizeof(buffer))
	     bytes = read(fd, buffer, sizeof(buffer));
	else
	     bytes = read(fd, buffer, size);
	if (bytes < 0)
	     goto err;
	if (!EVP_DigestUpdate(ctx, buffer, bytes))
	     goto err;
	size -= bytes;
    }
    if (SummaryOpt) {
	if (is_target)
	    CountTargetReadBytes += st.st_size;
	else
	    CountSourceReadBytes += st.st_size;
    }

    if (!EVP_DigestFinal(ctx, digest, &csum_len))
	goto err;

    if (!buf)
	buf = malloc(csum_len * 2 + 1);
    if (!buf)
	goto err;

    close(fd);
    EVP_MD_CTX_free(ctx);

    for (i = 0; i < csum_len; i++) {
	buf[2*i] = hex[digest[i] >> 4];
	buf[2*i+1] = hex[digest[i] & 0x0f];
    }
    buf[csum_len * 2] = '\0';

    return buf;

err:
    if (fd >= 0)
	close(fd);
    if (ctx != NULL)
	EVP_MD_CTX_free(ctx);
    return NULL;
}

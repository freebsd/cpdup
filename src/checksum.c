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
    char csum_Code[EVP_MAX_MD_SIZE * 2 + 1]; /* hex-encoded digest */
    int csum_Accessed;
} CSUMNode;

static CSUMNode *csum_lookup(const char *spath);
static void csum_cache(const char *spath, int sdirlen);
static void csum_load(FILE *fi);
static int csum_file(const EVP_MD *algo, const char *filename, char *buf, int is_target);

static char *CSUMSCache;		/* cache source directory name */
static CSUMNode *CSUMBase;
static int CSUMSCacheDirLen;
static int CSUMSCacheDirty;

void
csum_flush(void)
{
    CSUMNode *node;
    FILE *fo;

    if (CSUMSCacheDirty && CSUMSCache && !NotForRealOpt) {
	if ((fo = fopen(CSUMSCache, "w")) != NULL) {
	    for (node = CSUMBase; node; node = node->csum_Next) {
		if (node->csum_Accessed && node->csum_Code[0] != '\0') {
		    fprintf(fo, "%s %zu %s\n",
			node->csum_Code,
			strlen(node->csum_Name),
			node->csum_Name
		    );
		}
	    }
	    fclose(fo);
	} else {
	    logerr("Error writing checksum cache (%s): %s\n",
		   CSUMSCache, strerror(errno));
	}
    }

    CSUMSCacheDirty = 0;

    if (CSUMSCache) {
	while ((node = CSUMBase) != NULL) {
	    CSUMBase = node->csum_Next;

	    if (node->csum_Name != NULL)
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
     * Create new cache and load data if exists
     */
    CSUMSCacheDirLen = sdirlen;
    CSUMSCache = mprintf("%*.*s%s", sdirlen, sdirlen, spath, CsumCacheFile);
    if ((fi = fopen(CSUMSCache, "r")) != NULL) {
	csum_load(fi);
	fclose(fi);
    } else if (errno != ENOENT) {
	logerr("Error reading checksum cache (%s): %s\n",
	       CSUMSCache, strerror(errno));
    }
}

/*
 * csum_lookup:	lookup/create csum entry
 */
static CSUMNode *
csum_lookup(const char *spath)
{
    const char *sfile;
    int sdirlen;
    CSUMNode *node;

    if ((sfile = strrchr(spath, '/')) != NULL)
	++sfile;
    else
	sfile = spath;
    sdirlen = sfile - spath;

    csum_cache(spath, sdirlen);

    for (node = CSUMBase; node != NULL; node = node->csum_Next) {
	if (strcmp(sfile, node->csum_Name) == 0)
	    break;
    }
    if (node == NULL) {
	if ((node = malloc(sizeof(CSUMNode))) == NULL)
	    fatal("out of memory");

	memset(node, 0, sizeof(CSUMNode));
	node->csum_Name = strdup(sfile);
	node->csum_Next = CSUMBase;
	CSUMBase = node;
    }
    node->csum_Accessed = 1;
    return(node);
}

/*
 * csum_update:	force update the source checksum file.
 *
 *	Return -1 if failed
 *	Return 0  if up-to-date
 *	Return 1  if updated
 */
int
csum_update(const EVP_MD *algo, const char *spath)
{
    char scode[EVP_MAX_MD_SIZE * 2 + 1];
    int r;
    CSUMNode *node;

    node = csum_lookup(spath);

    if (csum_file(algo, spath, scode, 0 /* is_target */) == 0) {
	r = 0;
	if (strcmp(scode, node->csum_Code) != 0) {
	    r = 1;
	    memcpy(node->csum_Code, scode, sizeof(scode));
	    CSUMSCacheDirty = 1;
	}
    } else {
	r = -1;
    }

    return (r);
}

/*
 * csum_check:	check checksum against file
 *
 *	Return -1 if check failed
 *	Return 0  if source and dest files are identical
 *	Return 1  if source and dest files are not identical
 */
int
csum_check(const EVP_MD *algo, const char *spath, const char *dpath)
{
    char scode[EVP_MAX_MD_SIZE * 2 + 1];
    char dcode[EVP_MAX_MD_SIZE * 2 + 1];
    int r;
    CSUMNode *node;

    node = csum_lookup(spath);

    /*
     * The checksum file is used as a cache.
     */
    if (csum_file(algo, dpath, dcode, 1 /* is_target */) == 0) {
	r = 0;
	if (strcmp(node->csum_Code, dcode) != 0) {
	    r = 1;
	    /*
	     * Update the source digest code and recheck.
	     */
	    if (csum_file(algo, spath, scode, 0 /* is_target */) == 0) {
		if (strcmp(node->csum_Code, scode) != 0) {
		    memcpy(node->csum_Code, scode, sizeof(scode));
		    CSUMSCacheDirty = 1;
		    if (strcmp(node->csum_Code, dcode) == 0)
			r = 0;
		}
	    } else {
		r = -1;
	    }
	}
    } else {
	r = -1;
    }

    return(r);
}

/*
 * NOTE: buf will hold the hex-encoded digest and should have a size of
 *       >= (EVP_MAX_MD_SIZE * 2 + 1).
 */
static int
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = EVP_MD_CTX_new();
#else
    ctx = EVP_MD_CTX_create();
#endif
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

    close(fd);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_destroy(ctx);
#endif

    for (i = 0; i < csum_len; i++) {
	buf[2*i] = hex[digest[i] >> 4];
	buf[2*i+1] = hex[digest[i] & 0x0f];
    }
    buf[csum_len * 2] = '\0';

    return (0);

err:
    if (fd >= 0)
	close(fd);
    if (ctx != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(ctx);
#else
	EVP_MD_CTX_destroy(ctx);
#endif
    }
    return (-1);
}

static int
get_field(FILE *fi, int c, char *buf, size_t len)
{
    size_t n;

    n = 0;

    while (c != EOF) {
	if (c == ' ') {
	    buf[n] = '\0';
	    return (c);
	}

	buf[n++] = c;
	if (n == len)
	    break;

	c = fgetc(fi);
    }

    return (c);
}

static void
csum_load(FILE *fi)
{
    CSUMNode **pnode = &CSUMBase;
    CSUMNode *node;
    int c, n, nlen;
    char nbuf[sizeof("2147483647")];
    char *endp;

    /*
     * Line format: "<code> <name_len> <name>"
     * - code: hex-encoded digest
     * - name_len: 10-based integer indicating the length of the file name
     * - name: the file name (may contain special characters)
     * Example: "359d5608935488c8d0af7eb2a350e2f8 7 cpdup.c"
     */
    c = fgetc(fi);
    while (c != EOF) {
	node = malloc(sizeof(CSUMNode));
	if (node == NULL)
	    fatal("out of memory");
	memset(node, 0, sizeof(CSUMNode));

	c = get_field(fi, c, node->csum_Code, sizeof(node->csum_Code));
	if (c != ' ') {
	    logerr("Error parsing checksum cache (%s): invalid digest code (%c)\n",
		   CSUMSCache, c);
	    goto next;
	}

	c = fgetc(fi);
	c = get_field(fi, c, nbuf, sizeof(nbuf));
	if (c != ' ') {
	    logerr("Error parsing checksum cache (%s): invalid length (%c)\n",
		   CSUMSCache, c);
	    goto next;
	}
	nlen = (int)strtol(nbuf, &endp, 10);
	if (*endp != '\0' || nlen == 0) {
	    logerr("Error parsing checksum cache (%s): invalid length (%s)\n",
		   CSUMSCache, nbuf);
	    goto next;
	}

	if ((node->csum_Name = malloc(nlen + 1)) == NULL)
	    fatal("out of memory");
	node->csum_Name[nlen] = '\0';
	for (n = 0; n < nlen; n++) {
	    c = fgetc(fi);
	    if (c == EOF) {
		logerr("Error parsing checksum cache (%s): invalid filename\n",
		       CSUMSCache);
		goto next;
	    }
	    node->csum_Name[n] = c;
	}

	c = fgetc(fi);
	if (c != '\n' && c != EOF) {
	    logerr("Error parsing checksum cache (%s): trailing garbage (%c)\n",
		   CSUMSCache, c);
	    while (c != EOF && c != '\n')
		c = fgetc(fi);
	}
	if (c == '\n')
	    c = fgetc(fi);

	node->csum_Accessed = 1;
	*pnode = node;
	pnode = &node->csum_Next;

	if (SummaryOpt) {
	    CountSourceReadBytes += strlen(node->csum_Code) + strlen(nbuf) +
		nlen + 1;
	}
	continue;

    next:
	if (node->csum_Name != NULL)
	    free(node->csum_Name);
	free(node);
	while (c != EOF && c != '\n')
	    c = fgetc(fi);
	if (c == '\n')
	    c = fgetc(fi);
    }
}

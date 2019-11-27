/*
 * md5.h        Structures and prototypes for md5.
 *
 * Version:     $Id: md5.h,v 1.2 2013/04/08 11:53:33 liminyi Exp $
 * License:		LGPL, but largely derived from a public domain source.
 *
 */



/*  The below was retrieved from
 *  http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/crypto/md5.h?rev=1.1
 *  With the following changes: uint64_t => u32[2]
 *  Commented out #include <sys/cdefs.h>
 *  Commented out the __BEGIN and __END _DECLS, and the __attributes.
 */

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */
#ifndef _LIB_MD5_H
#define _LIB_MD5_H

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16
#ifndef u32
typedef unsigned int u32;
#endif
typedef unsigned char u8;
typedef struct MD5Context {
	u32 state[4];			/* state */
	u32 count[2];			/* number of bits, mod 2^64 */
	u8 buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} MD5_CTX;


void	 MD5Init(MD5_CTX *);
void	 MD5Update(MD5_CTX *, const u8 *, size_t);
void	 MD5Final(u8 [MD5_DIGEST_LENGTH], MD5_CTX *);
void	 MD5Transform(u32 [4], const u8 [MD5_BLOCK_LENGTH]);

void md5_calc(unsigned char *output, unsigned char *input,
		     unsigned int inputlen);

#endif /* _LIB_MD5_H */

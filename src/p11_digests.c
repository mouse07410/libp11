/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2017 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <stdio.h>
#include <memory.h>
#include <inttypes.h>
#include "libp11-int.h"

/* TODO: implement the rest of DIGESTS functionality *here* */

/* orig_pkey_meth_rsa holds the original pkey methods */
//static EVP_PKEY_METHOD *orig_pkey_meth_rsa = NULL;

/* direct pointers to original methods to fall back to if needed */
//static pkey_rsa_decrypt_t orig_pkey_rsa_decrypt = NULL;
//static pkey_rsa_encrypt_t orig_pkey_rsa_encrypt = NULL;

extern int rsa_ex_index;

/* Forward declaration of our custom pkcs11 pkey methods */
//int pkcs11_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
//		unsigned char *out, size_t *outlen,
//		const unsigned char *in, size_t inlen);

static EVP_PKEY_METHOD *pkcs11_engine_digests()
{
	EVP_PKEY_METHOD *orig_pmeth = NULL;
	EVP_PKEY_METHOD *pmeth      = NULL;

	int (*psign_init) (EVP_PKEY_CTX *ctx) = NULL;
	int (*pdecr_init) (EVP_PKEY_CTX *ctx) = NULL;
	int (*pencr_init) (EVP_PKEY_CTX *ctx) = NULL;
    int (*psctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *md_ctx) = NULL;

	int (*psign) (EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen) = NULL;
	int (*pdecr) (EVP_PKEY_CTX *ctx,
			unsigned char *out, size_t *outlen,
			const unsigned char *in, size_t inlen) = NULL;
	int (*pencr) (EVP_PKEY_CTX *ctx,
			unsigned char *out, size_t *outlen,
			const unsigned char *in, size_t inlen) = NULL;
    int (*psctx) (EVP_PKEY_CTX *ctx,
            unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) = NULL;

	/* Retrieve original methods and create placeholder for custom ones */
	if (!(orig_pmeth = (EVP_PKEY_METHOD *) EVP_PKEY_meth_find(EVP_PKEY_RSA))) {
		fprintf(stderr, "%s:%d failed to retrieve EVP_PKEY_RSA methods!\n",
				__FILE__, __LINE__);
		goto err;
	}
	if (!(pmeth = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN))) {
		fprintf(stderr, "%s:%d failed to create new EVP_PKEY_RSA!\n",
				__FILE__, __LINE__);
		goto err;
	}
	EVP_PKEY_meth_copy(pmeth, orig_pmeth);

	/* Check to make sure we haven't already hooked the original methods */
	if (orig_pkey_meth_rsa)
		return pmeth; /* everything was done before this invocation */
	else
		orig_pkey_meth_rsa = orig_pmeth;

	/* Retrieve original methods */
	EVP_PKEY_meth_get_sign(orig_pmeth,    &psign_init, &psign);
	EVP_PKEY_meth_get_decrypt(orig_pmeth, &pdecr_init, &pdecr);
	EVP_PKEY_meth_get_encrypt(orig_pmeth, &pencr_init, &pencr);
    EVP_PKEY_meth_get_signctx(orig_pmeth, &psctx_init, &psctx);

	if (!psign || !pdecr || !pencr) {
		fprintf(stderr, "%s:%d failed to get one of orig rsa methods "
				"psign=%p pdecr=%p pencr=%p\n", __FILE__, __LINE__,
				(void*)psign, (void*)pdecr, (void*)pencr);
		goto err;
	}

	/* Set "original" method pointers so pcs11 operations can fall back */
	/* to call them if our methods do not support the requested padding */
	orig_pkey_rsa_sign    = psign;
	orig_pkey_rsa_decrypt = pdecr;
	orig_pkey_rsa_encrypt = pencr;
    orig_pkey_rsa_sctxini = psctx_init; /* possibly/probably NULL */
    orig_pkey_rsa_signctx = psctx;      /* possibly/probably NULL */

	/* Hook our custom PSS- an OAEP-aware methods */
	EVP_PKEY_meth_set_sign(pmeth, psign_init, pkcs11_pkey_rsa_sign);
	EVP_PKEY_meth_set_decrypt(pmeth, pdecr_init, pkcs11_pkey_rsa_decrypt);
	EVP_PKEY_meth_set_encrypt(pmeth, pencr_init, pkcs11_pkey_rsa_encrypt);
    /* nothing yet to override signctx_init() and signctx() - it's WIP */
    
	return pmeth;

err:
	fprintf(stderr, "%s:%d creating custom evp_pkey_rsa failed\n", __FILE__, __LINE__);
	return NULL;
}

int PKCS11_engine_digests(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
	if (pkey_method_rsa == NULL)
		pkey_method_rsa = pkcs11_pkey_method_rsa();
	if (pkey_method_rsa == NULL)
		return 0;
	if (!pmeth) { /* get the list of supported nids */
		*nids = pkey_nids;
		return 1; /* the number of returned nids */
	}
	/* get the EVP_PKEY_METHOD */
	if (nid == EVP_PKEY_RSA) {
		*pmeth = pkey_method_rsa;
		return 1; /* success */
	}
	*pmeth = NULL;
	return 0;
}

/*
 * Support for RSA-PKCS-OAEP decryption
 */
int pkcs11_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	int ret;
	unsigned char out_buf[20480];
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	const EVP_MD *oaep_md = NULL, *mgf1_md = NULL;
	int pad = -1;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	ASN1_STRING *os = NULL;
	CK_RV rv = 0;
	CK_MECHANISM  mechanism;
	CK_ULONG size = *outlen;
	PKCS11_KEY *key = NULL;
	PKCS11_SLOT *slot = NULL;
	PKCS11_CTX *ctx = NULL;
	PKCS11_KEY_private *kpriv = NULL;
	PKCS11_SLOT_private *spriv = NULL;

	CK_MECHANISM_TYPE *mechs = NULL;
	CK_ULONG num_mechs = 0;

#if defined(DEBUG)
	fprintf(stderr, "%s:%d pkcs11_pkey_rsa_decrypt() out=%p "
			" *outlen=%lu in=%p inlen=%lu\n",
			__FILE__, __LINE__, out, *outlen, in, inlen);
#endif

	if (!(pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx)) ||
			!(rsa = EVP_PKEY_get1_RSA(pkey)) ||
			!(key = RSA_get_ex_data(rsa, rsa_ex_index))) {
		fprintf(stderr, "%s:%d got NULL pkey=%p rsa=%p key=%p\n",
				__FILE__, __LINE__, (void*)pkey, (void*)rsa, (void*)key);
		goto do_original;
	}


	slot  = KEY2SLOT(key);
	ctx   = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);

	memset(&mechanism, 0, sizeof(CK_MECHANISM));
	memset(&oaep_params, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
	memset(out_buf, 0, sizeof(out_buf));

	size = sizeof(out_buf);

	/* Get the padding type */
	EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &pad);
#if defined(DEBUG)
	fprintf(stderr, "%s:%d padding=%d\n", __FILE__, __LINE__, pad);
#endif

	switch (pad) {
		case RSA_PKCS1_OAEP_PADDING:
#if defined(DEBUG)
			fprintf(stderr, "RSA_OAEP\n");
#endif
			if (EVP_PKEY_CTX_get_rsa_oaep_md(evp_pkey_ctx, &oaep_md) <= 0)
				goto do_original;
			if (EVP_PKEY_CTX_get_rsa_mgf1_md(evp_pkey_ctx, &mgf1_md) <= 0)
				goto do_original;
#if defined(DEBUG)
			fprintf(stderr, "%s:%d hashAlg=%s mgf=MGF1-%s \n",
					__FILE__, __LINE__, EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md));
#endif
			/* make up a CK_MECHANISM */
			if (!set_pss_oaep_md_and_mgf1(&oaep_params, oaep_md, mgf1_md, pad)) {
#if defined(DEBUG)
				fprintf(stderr, "%s:%d failed to fill oaep_params with md and mgf "
						"values (md=%s mgf=MGF1-%s)\n",
						__FILE__, __LINE__, EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md));
#endif
				goto do_original;
			}

			/* These settings are compatible with OpenSSL 1.0.2L and 1.1.0+ */
			/* We do not support OAEP "label" parameter yet... */
			oaep_params.source = 0UL;  /* empty parameter (label) */
			oaep_params.pSourceData = NULL;
			oaep_params.ulSourceDataLen = 0;

			mechanism.mechanism = CKM_RSA_PKCS_OAEP;
			mechanism.pParameter = &oaep_params;
			mechanism.ulParameterLen = sizeof(oaep_params);

			break;

			/* Add future paddings here */
			/* TODO we could do any RSA padding here too! */
		case CKM_RSA_PKCS:
			mechanism.pParameter = NULL;
			mechanism.ulParameterLen = 0;
			break;
		default:
#if defined(DEBUG)
			fprintf(stderr, "not RSA-OAEP padding: %d\n", pad);
#endif
			goto do_original;
	} /* end switch(pad) */

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);

	rv = CRYPTOKI_call(ctx,
			C_DecryptInit(spriv->session, &mechanism, kpriv->object));

#if defined(DEBUG)
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
		fprintf(stderr, "%s:%d C_DecryptInit returned %lu\n", __FILE__, __LINE__, rv);
#endif
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) goto unlock;
	if (rv == CKR_USER_NOT_LOGGED_IN || kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key); /* don't re-auth unless flag is set! */
	if (!rv)
		rv = CRYPTOKI_call(ctx,
				C_Decrypt(spriv->session, (CK_BYTE *) in, inlen, (CK_BYTE_PTR) out_buf, &size));
#if defined(DEBUG)
	if (rv != CKR_OK)
		fprintf(stderr, "%s:%d C_Decrypt returned %lu\n", __FILE__, __LINE__, rv);
#endif

	/* we will check rv after unlocking */

unlock:
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);

	if (rv != CKR_OK)
		goto do_original;

	if (out != NULL) { /* real decryption request - not just a query for output size */
		/* Validate output buffer size before copying to there */
		/* Because if the output buffer was provided - its size "*outlen" should */
		/* be meaningful                                                         */
		if (*outlen < size) {
			fprintf(stderr, "pkcs11_pkey_rsa_decrypt(): for %d padding "
					"output buffer (%lu bytes) too small! (need %lu)\n",
					pad, *outlen, size);
			return -1;
		}
		memcpy(out, out_buf, size);
	}
	/* Make sure we aren't overstepping provided output buffer size */
	if (*outlen >= size || out == NULL || *outlen == 0)
		*outlen = size;

	return 1;

do_original:
	if (rsa) RSA_free(rsa);

	/* To accommodate for OpenSSL inability to deal with out==NULL when */
	/* the key is engine-provided rather than taken from a disk file,   */
	/* but the token does not support the padding, so it has to be done */
	/* by the original pley_rsa_decrypt()                               */
	if (out == NULL || *outlen == 0) {
		rv = (*orig_pkey_rsa_decrypt)(evp_pkey_ctx, out_buf, &size, in, inlen);
		if (rv > 0) {
			*outlen = size;
			return 1;
		} else
			return rv;
	} else
		return (*orig_pkey_rsa_decrypt)(evp_pkey_ctx, out, outlen, in, inlen);
}


/*
 * Support for RSA-PKCS-OAEP encryption
 * Main purpose for now: handling out==NULL case
 */
int pkcs11_pkey_rsa_encrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	unsigned char out_buf[20480];
	EVP_PKEY *pkey = NULL;
	int rv = 0;
	CK_ULONG size = sizeof(out_buf);

#if defined(DEBUG)
	fprintf(stderr, "%s:%d pkcs11_pkey_rsa_encrypt(): out=%p *outlen=%lu "
			" in=%p inlen=%lu\n", __FILE__, __LINE__, out, *outlen, in, inlen);
#endif /* DEBUG */
	memset(out_buf, 0, sizeof(out_buf));

	/* To accommodate for OpenSSL inability to deal with out==NULL when */
	/* the key is engine-provided rather than taken from a disk file,   */
	/* but the token does not support the padding, so it has to be done */
	/* by the original pley_rsa_decrypt()                               */
	if (out == NULL || *outlen == 0) {
		rv = (*orig_pkey_rsa_encrypt)(evp_pkey_ctx, out_buf, &size, in, inlen);
		if (rv > 0) {
#if defined(DEBUG)
			fprintf(stderr, "%s:%d pkcs11_pkey_rsa_encrypt(): orig_pkey_rsa_encrypt returned %d (%lu)\n",
					__FILE__, __LINE__, rv, size);
#endif /* DEBUG */
			*outlen = size;
			return 1;
		} else {

#if defined(DEBUG)
			fprintf(stderr, "%s:%d pkcs11_pkey_rsa_encrypt(): orig_pkey_rsa_encrypt returned %d (%lu)\n",
					__FILE__, __LINE__, rv, size);
#endif /* DEBUG */
			return rv;
		}
	} else {
		rv = (*orig_pkey_rsa_encrypt)(evp_pkey_ctx, out, outlen, in, inlen);
#if defined(DEBUG)
		fprintf(stderr, "%s:%d pkcs11_pkey_rsa_encrypt(): orig_pkey_rsa_encrypt returned %d (%lu)\n",
				__FILE__, __LINE__, rv, *outlen);
#endif /* DEBUG */
		return rv;
	}

	return 0;  /* to silence compiler warning */
}



/* vim: set noexpandtab: */

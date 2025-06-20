// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/cred.h>
#include <linux/key.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>
#include "objsec.h"
#include "code_sign_ext.h"
#include "code_sign_ioctl.h"
#include "code_sign_log.h"
#include "verify_cert_chain.h"

#ifdef CONFIG_SECURITY_XPM
#include "dsmm_developer.h"
#endif

/*
 * Find the key (X.509 certificate) to use to verify a PKCS#7 message.  PKCS#7
 * uses the issuer's name and the issuing certificate serial number for
 * matching purposes.  These must match the certificate issuer's name (not
 * subject's name) and the certificate serial number [RFC 2315 6.7].
 */
static int pkcs7_find_key(struct pkcs7_message *pkcs7,
			  struct pkcs7_signed_info *sinfo)
{
	struct x509_certificate *cert;
	unsigned certix = 1;

	kenter("%u", sinfo->index);
	code_sign_log_info("sinfo->index %u", sinfo->index);

	cert = pkcs7->certs;
	while (cert) {
		if (asymmetric_key_id_same(cert->id, sinfo->sig->auth_ids[0])) {
			if (strcmp(cert->pub->pkey_algo, sinfo->sig->pkey_algo) != 0
					&& (strncmp(cert->pub->pkey_algo, "ecdsa-", 6) != 0
					|| strcmp(cert->sig->pkey_algo, "ecdsa") != 0)) {
				code_sign_log_warn("sig %u: X.509 algo and PKCS#7 sig algo don't match", sinfo->index);
				cert = cert->next;
				certix++;
				continue;
			}
		} else {
			code_sign_log_warn("sig %u: X.509->id and PKCS#7 sinfo->sig->auth_ids[0] don't match",
				sinfo->index, cert->id, sinfo->sig->auth_ids[0]);
			cert = cert->next;
			certix++;
			continue;
		}

		// cert is found
		sinfo->signer = cert;
		return 0;
	}

	/* The relevant X.509 cert isn't found here, but it might be found in
	 * the trust keyring.
	 */
	code_sign_log_info("Sig %u: Issuing X.509 cert not found (#%*phN)",
		 sinfo->index,
		 sinfo->sig->auth_ids[0]->len, sinfo->sig->auth_ids[0]->data);
	return 0;
}

static void set_file_ownerid(struct cs_info *cs_info, int path_type,
	struct pkcs7_signed_info *sinfo)
{
	if (cs_info == NULL)
		return;

	/* Mark a debug file as OWNERID_DEBUG */
	if((path_type > DEBUG_CODE_START) && (path_type < DEBUG_CODE_END)) {
		code_sign_set_ownerid(cs_info, FILE_OWNERID_DEBUG, NULL, 0);
		return;
	}

	/* Mark the file as OWNERID_COMPAT, if its ownerid is empty */
	if(!sinfo->ownerid) {
		code_sign_set_ownerid(cs_info, FILE_OWNERID_COMPAT, NULL, 0);
		return;
	}

	/* Mark the file as OWNERID_SHARED, if the file is shareable */
	if((sinfo->ownerid_len == strlen(OWNERID_SHARED_TAG)) &&
		!memcmp(sinfo->ownerid, OWNERID_SHARED_TAG,
			sinfo->ownerid_len)) {
		code_sign_set_ownerid(cs_info, FILE_OWNERID_SHARED, NULL, 0);
		return;
	}

	/* If this code is signed on the device, check whether it is DEBUG_ID */
	if((path_type = MAY_LOCAL_CODE) &&
		(sinfo->ownerid_len == strlen(OWNERID_DEBUG_TAG)) &&
		!memcmp(sinfo->ownerid, OWNERID_DEBUG_TAG,
			sinfo->ownerid_len)) {
		code_sign_set_ownerid(cs_info, FILE_OWNERID_DEBUG, NULL, 0);
		return;
	}

	/* Mark the file OWNERID_APP in other cases */
	code_sign_set_ownerid(cs_info, FILE_OWNERID_APP,
		sinfo->ownerid, sinfo->ownerid_len);
}

static struct cert_source *find_matched_source(const struct x509_certificate *signer, bool is_debug)
{
	int block_type = is_debug ? DEBUG_BLOCK_CODE: RELEASE_BLOCK_CODE;
	struct cert_source *source = find_match(signer->subject, signer->issuer, is_debug);

	if (source == NULL) {
		source = find_match("ALL", signer->issuer, is_debug);
	} else if (source->path_type == block_type) {
		code_sign_log_error("signer certificate's type not trusted");
		return NULL;
	}
	return source;
}

void code_sign_verify_certchain(const void *raw_pkcs7, size_t pkcs7_len,
	struct fsverity_info *vi, int *ret)
{
	struct pkcs7_message *pkcs7;
	struct pkcs7_signed_info *sinfo;

	pkcs7 = pkcs7_parse_message(raw_pkcs7, pkcs7_len);
	if (IS_ERR(pkcs7)) {
		code_sign_log_error("parse pkcs7 message failed");
		*ret = PTR_ERR(pkcs7);
		return;
	}

	if (!pkcs7->signed_infos) {
		code_sign_log_error("signed info not found in pkcs7");
		goto untrusted;
	}

	// no cert chain, verify by certificates in keyring
	if (!pkcs7->certs) {
		code_sign_log_warn("no certs in pkcs7, might be found in trust keyring");
		*ret = MAY_LOCAL_CODE;
		goto exit;
	}

	bool is_dev_mode = false;

#ifdef CONFIG_SECURITY_XPM
	// developer mode && developer proc
	if (get_developer_mode_state() == STATE_ON) {
		code_sign_log_info("developer mode on");
		is_dev_mode = true;
	}
#endif

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		/* Find the key for the signature if there is one */
		*ret = pkcs7_find_key(pkcs7, sinfo);
		if (*ret) {
			code_sign_log_error("key not find in pkcs7");
			goto exit;
		}

		const struct x509_certificate *signer = sinfo->signer;
		if (!signer) {
			code_sign_log_error("signer cert not found in pkcs7");
			*ret = -EINVAL;
			goto exit;
		}

		struct cert_source *source = find_matched_source(signer, false);
		if (!source) {
			if (is_dev_mode) {
				// find on dev trusted list
				source = find_matched_source(signer, true);
				if (!source)
					goto untrusted;
			} else {
				goto untrusted;
			}
		}

		// cal cert chain depth
		int cert_chain_depth_without_root = 1;
		char *issuer = signer->issuer;
		struct x509_certificate* cert = pkcs7->certs;
		while(cert) {
			// if issuer cert is found
			if (cert->subject && (strcmp(cert->subject, issuer) == 0)) {
				// reach root CA, end search
				if (strcmp(cert->subject, cert->issuer) == 0) {
					break;
				}
				cert_chain_depth_without_root++;
				// search again for current issuer's issuer
				issuer = cert->issuer;
				cert = pkcs7->certs;
			} else {
				// move to next certificate
				cert = cert->next;
			}
		}
		if (cert_chain_depth_without_root == (source->max_path_depth - 1)) {
			code_sign_log_info("cert subject and issuer trusted");
			set_file_ownerid(&vi->fcs_info, source->path_type, pkcs7->signed_infos);
			*ret = source->path_type;
			goto exit;
		} else {
			code_sign_log_error("depth mismatch: cert chain depth without root is %d, max_path_depth is %d",
				cert_chain_depth_without_root, source->max_path_depth);
		}
	}

untrusted:
	code_sign_log_error("cert subject and issuer verify failed");
	*ret = -EKEYREJECTED;
exit:
	pkcs7_free_message(pkcs7);
}

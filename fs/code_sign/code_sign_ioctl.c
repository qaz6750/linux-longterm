// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/compat.h>
#include <linux/version.h>
#include "avc.h"
#include "objsec.h"
#include "code_sign_ioctl.h"
#include "code_sign_log.h"
#define  MAX_SIGNING_LENGTH 2048

DEFINE_SPINLOCK(cert_chain_tree_lock);
struct rb_root cert_chain_tree = RB_ROOT;
struct rb_root dev_cert_chain_tree = RB_ROOT;

struct cert_source *matched_cert_search(struct rb_root *root, const char *subject, const char *issuer)
{
	struct rb_node **cur_node = &(root->rb_node);

	while (*cur_node) {
		struct cert_source *cur_cert = container_of(*cur_node, struct cert_source, node);
		int result = strcmp(subject, cur_cert->subject);

		if (result < 0) {
			cur_node = &((*cur_node)->rb_left);
		} else if (result > 0) {
			cur_node = &((*cur_node)->rb_right);
		} else {
			result = strcmp(issuer, cur_cert->issuer);
			if (result < 0) {
				cur_node = &((*cur_node)->rb_left);
			} else if (result > 0) {
				cur_node = &((*cur_node)->rb_right);
			} else {
				code_sign_log_info("cert found");
				return cur_cert;
			}
		}
	}
	code_sign_log_error("cert not found");
	return NULL;
}

struct cert_source *cert_chain_search(struct rb_root *root, const char *subject, const char *issuer, bool has_locked)
{
	if (has_locked)
		return matched_cert_search(root, subject, issuer);
	else {
		spin_lock(&cert_chain_tree_lock);
		struct cert_source *matched_cert = matched_cert_search(root, subject, issuer);
		spin_unlock(&cert_chain_tree_lock);
		return matched_cert;
	}
}

struct cert_source *find_match(const char *subject, const char *issuer, bool is_dev)
{
	if (is_dev)
		return cert_chain_search(&dev_cert_chain_tree, subject, issuer, false);
	else
		return cert_chain_search(&cert_chain_tree, subject, issuer, false);
}

int code_sign_check_caller(char *caller)
{
	u32 sid = current_sid(), context_len;
	char *context = NULL;
	int rc;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	rc = security_sid_to_context(&selinux_state, sid, &context, &context_len);
#else
	rc = security_sid_to_context(sid, &context, &context_len);
#endif
	if (rc)
		return -EINVAL;

	code_sign_log_debug("sid=%d, context=%s", sid, context);
	if (!strncmp(caller, context, strlen(caller)))
		return 0;

	return -EPERM;
}

int cert_chain_insert(struct rb_root *root, struct cert_source *cert)
{
	int ret = code_sign_check_caller(KEY_ENABLE_CTX);
	if (ret == -EINVAL) {
		code_sign_log_error("load SELinux context failed");
		return -EINVAL;
	} else if (ret == -EPERM) {
		// procs except key_enable are only allowed to insert developer_code
		if (!(cert->path_type == RELEASE_DEVELOPER_CODE
			|| cert->path_type == DEBUG_DEVELOPER_CODE)) {
			code_sign_log_error("no permission to insert code %d", cert->path_type);
			return -EPERM;
		}
	}

	spin_lock(&cert_chain_tree_lock);
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct cert_source *this = container_of(*new, struct cert_source, node);
		int result = strcmp(cert->subject, this->subject);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			result = strcmp(cert->issuer, this->issuer);
			if (result < 0) {
				new = &((*new)->rb_left);
			} else if (result > 0) {
				new = &((*new)->rb_right);
			} else {
				this->cnt++;
				code_sign_log_info("cert already exist in trust sources");
				goto out;
			}
		}
	}

	// add new node
	cert->cnt++;
	rb_link_node(&cert->node, parent, new);
	rb_insert_color(&cert->node, root);

	code_sign_log_info("add trusted cert: subject = '%s', issuer = '%s', max_path_depth = %d",
		cert->subject, cert->issuer, cert->max_path_depth);
out:
	spin_unlock(&cert_chain_tree_lock);
	return 0;
}

int cert_chain_remove(struct rb_root *root, struct cert_source *cert)
{
	spin_lock(&cert_chain_tree_lock);
	struct cert_source *matched_cert = cert_chain_search(root, cert->subject, cert->issuer, true);

	int ret = 0;
	if (!matched_cert) {
		ret = -EINVAL;
		goto out;
	}

	if (matched_cert->path_type == RELEASE_DEVELOPER_CODE
		|| matched_cert->path_type == DEBUG_DEVELOPER_CODE) {
		--matched_cert->cnt;
		if (matched_cert->cnt > 0)
			goto out;
		rb_erase(&matched_cert->node, root);
		code_sign_log_info("remove trusted cert: subject = '%s', issuer = '%s', max_path_depth = %d",
			cert->subject, cert->issuer, cert->max_path_depth);
		goto out;
	}

	code_sign_log_error("can not remove cert type %x", cert->path_type);
	ret = -EKEYREJECTED;
out:
	spin_unlock(&cert_chain_tree_lock);
	return ret;
}

int code_sign_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int code_sign_release(struct inode *inode, struct file *filp)
{
	return 0;
}

int code_sign_avc_has_perm(u16 tclass, u32 requested)
{
	struct av_decision avd;
	u32 sid = current_sid();
	int rc, rc2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	rc = avc_has_perm_noaudit(&selinux_state, sid, sid, tclass, requested,
		AVC_STRICT, &avd);
	rc2 = avc_audit(&selinux_state, sid, sid, tclass, requested, &avd, rc,
		NULL, AVC_STRICT);
#else
	rc = avc_has_perm_noaudit(sid, sid, tclass, requested,
		AVC_STRICT, &avd);
	rc2 = avc_audit(sid, sid, tclass, requested, &avd, rc,
		NULL);
#endif
	if (rc2)
		return rc2;

	return rc;
}

int parse_cert_source(unsigned long args, struct cert_source **_source)
{
	int ret = 0;
	struct cert_source *source = kzalloc(sizeof(struct cert_source), GFP_KERNEL);

	if (!source)
		return -ENOMEM;

	struct cert_chain_info info;

	if (copy_from_user(&info, args, sizeof(struct cert_chain_info))) {
		code_sign_log_error("cmd copy_from_user failed");
		ret = -ENOMEM;
		goto copy_source_failed;
	}

	if (info.path_len > CERT_CHAIN_PATH_LEN_MAX || info.issuer_length == 0 || info.signing_length == 0 
		|| info.issuer_length > MAX_SIGNING_LENGTH || info.signing_length > MAX_SIGNING_LENGTH) {
		code_sign_log_error("invalid path len or subject or issuer");
		ret = -EINVAL;
		goto copy_source_failed;
	}

	source->subject = kzalloc(info.signing_length + 1, GFP_KERNEL);
	if (!source->subject) {
		ret = -ENOMEM;
		goto copy_source_failed;
	}

	if (copy_from_user(source->subject, u64_to_user_ptr(info.signing_ptr), info.signing_length)) {
		code_sign_log_error("copy_from_user get signing failed");
		ret = -EFAULT;
		goto copy_subject_failed;
	}

	source->issuer = kzalloc(info.issuer_length + 1, GFP_KERNEL);
	if (!source->issuer) {
		ret = -ENOMEM;
		goto copy_subject_failed;
	}

	ret = copy_from_user(source->issuer, u64_to_user_ptr(info.issuer_ptr), info.issuer_length);
	if (ret) {
		code_sign_log_error("copy_from_user get issuer failed");
		ret = -EFAULT;
		goto copy_issuer_failed;
	}

	source->max_path_depth = info.path_len;
	source->path_type = info.cert_type;

	*_source = source;
	return ret;

copy_issuer_failed:
	kfree(source->issuer);
copy_subject_failed:
	kfree(source->subject);
copy_source_failed:
	kfree(source);
	return ret;
}

int code_sign_check_code(int code)
{
	if (code > RELEASE_CODE_START && code < RELEASE_CODE_END)
		return 0;

	if (code > DEBUG_CODE_START && code < DEBUG_CODE_END)
		return 1;

	code_sign_log_error("cert type %x is invalid", code);
	return -EINVAL;
}

long code_sign_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret = 0;
	struct cert_source *source;

	switch (cmd) {
		case ADD_CERT_CHAIN:
			if (code_sign_avc_has_perm(SECCLASS_CODE_SIGN, CODE_SIGN__ADD_CERT_CHAIN)) {
				code_sign_log_error("selinux check failed, no permission to add cert chain");
				return -EPERM;
			}

			ret = parse_cert_source(args, &source);
			if (ret)
				return ret;

			// insert rb_tree
			ret = code_sign_check_code(source->path_type);
			if (ret < 0)
				return ret;

			if (ret == 1) {
				// developer cert
				code_sign_log_debug("add developer cert");
				ret = cert_chain_insert(&dev_cert_chain_tree, source);
			} else {
				code_sign_log_debug("add release cert");
				ret = cert_chain_insert(&cert_chain_tree, source);
			}
			break;
		case REMOVE_CERT_CHAIN:
			if (code_sign_avc_has_perm(SECCLASS_CODE_SIGN, CODE_SIGN__REMOVE_CERT_CHAIN)) {
				code_sign_log_error("selinux check failed, no permission to remove cert chain");
				return -EPERM;
			}

			ret = parse_cert_source(args, &source);
			if (ret)
				return ret;

			// delete rb_tree
			ret = code_sign_check_code(source->path_type);
			if (ret < 0)
				return ret;

			if (ret == 1) {
				// developer cert
				code_sign_log_debug("remove developer cert");
				ret = cert_chain_remove(&dev_cert_chain_tree, source);
			} else {
				code_sign_log_debug("remove release cert");
				ret = cert_chain_remove(&cert_chain_tree, source);
			}
			if (ret) {
				code_sign_log_error("remove cert failed.");
			}
			break;
		default:
			code_sign_log_error("code_sign cmd error, cmd: %d", cmd);
			ret = -EINVAL;
			break;
	}

	return ret;
}

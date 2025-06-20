// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <asm/byteorder.h>
#include <linux/version.h>
#include <linux/fsverity.h>
#include <linux/slab.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <linux/pagemap.h>
#endif

#include "code_sign_elf.h"
#include "code_sign_log.h"
#include "verify_cert_chain.h"

#ifdef CONFIG_SECURITY_XPM
#include "dsmm_developer.h"
#endif

#define SIGN_HEAD_SIZE (sizeof(sign_head_t))

static void parse_sign_head(sign_head_t *out, char *ptr)
{
	sign_head_t *tmp_data = (sign_head_t *) ptr;
	/* magic and version are in byte represention */
	strncpy(out->magic, tmp_data->magic, sizeof(tmp_data->magic));
	strncpy(out->version, tmp_data->version, sizeof(tmp_data->version));
	out->sign_data_size = le32_to_cpu(tmp_data->sign_data_size);
	out->sign_block_num = le32_to_cpu(tmp_data->sign_block_num);
	out->padding = le32_to_cpu(tmp_data->padding);
}

static void parse_tl_hdr(tl_header_t *out, char *ptr)
{
	tl_header_t *tmp_data = (tl_header_t *) ptr;
	out->type = le32_to_cpu(tmp_data->type);
	out->length = le32_to_cpu(tmp_data->length);
}

static void parse_block_hdr(block_hdr_t *out, char *ptr)
{
	block_hdr_t *tmp = (block_hdr_t *) ptr;
	out->type = le32_to_cpu(tmp->type);
	out->length = le32_to_cpu(tmp->length);
	out->offset = le32_to_cpu(tmp->offset);
}

static int get_block_headers(sign_block_t *sign_block, char *sign_data_ptr)
{
	/* parse all block headers */
	for (int i = 0; i < sign_block->sign_head.sign_block_num; i++) {
		block_hdr_t *tmp_block_hdr = (block_hdr_t *) (sign_data_ptr + sizeof(block_hdr_t) * i);
		if (BLOCK_TYPE_CODE_SIGNING == le32_to_cpu(tmp_block_hdr->type)) {
			parse_block_hdr(&sign_block->code_signing_block_hdr, sign_data_ptr + sizeof(block_hdr_t) * i);
		} else if (BLOCK_TYPE_SIGNED_PROFILE == le32_to_cpu(tmp_block_hdr->type)) {
			parse_block_hdr(&sign_block->profile_block_hdr, sign_data_ptr + sizeof(block_hdr_t) * i);
		} else {
			code_sign_log_error("block type invalid: %u", le32_to_cpu(tmp_block_hdr->type));
		}
	}
	if (sign_block->code_signing_block_hdr.type != BLOCK_TYPE_CODE_SIGNING) {
		code_sign_log_error("code signing block header not exist");
		return -EINVAL;
	}
	if (sign_block->code_signing_block_hdr.offset + sizeof(tl_header_t) > sign_block->sign_head.sign_data_size) {
		code_sign_log_error("code signing block offset invalid: %u", sign_block->code_signing_block_hdr.offset);
		return -EINVAL;
	}
	return 0;
}

static int get_merkle_tree(sign_block_t *sign_block, char *sign_data_ptr)
{
	parse_tl_hdr(&sign_block->merkle_tree_hdr, sign_data_ptr + sign_block->code_signing_block_hdr.offset);
	if (sign_block->merkle_tree_hdr.type != TYPE_MERKLE_TREE) {
		code_sign_log_error("merkle tree type invalid: %u", sign_block->merkle_tree_hdr.type);
		return -EINVAL;
	}
	if (sign_block->merkle_tree_hdr.length + sizeof(tl_header_t)
		> sign_block->sign_head.sign_data_size - sign_block->code_signing_block_hdr.offset - sizeof(tl_header_t)) {
		code_sign_log_error("merkle tree data length invalid: %u", sign_block->merkle_tree_hdr.length);
		return -EINVAL;
	}
	return 0;
}

static int get_fsverity_desc(sign_block_t *sign_block, char *sign_data_ptr)
{
	/* parse fsverity header and fsverity descriptor */
	parse_tl_hdr(&sign_block->fsverity_desc_hdr, sign_data_ptr + sign_block->code_signing_block_hdr.offset
												 + sizeof(tl_header_t) + sign_block->merkle_tree_hdr.length);
	if (sign_block->fsverity_desc_hdr.type != TYPE_FS_VERITY_DESC) {
		code_sign_log_error("fsverity desc type invalid: %u", sign_block->fsverity_desc_hdr.type);
		return -EINVAL;
	}
	if (sign_block->fsverity_desc_hdr.length
		> sign_block->sign_head.sign_data_size - sign_block->code_signing_block_hdr.offset
		  - sizeof(tl_header_t) - sign_block->merkle_tree_hdr.length - sizeof(tl_header_t)) {
		code_sign_log_error("fsverity desc length invalid: %u", sign_block->fsverity_desc_hdr.length);
		return -EINVAL;
	}

	sign_block->fsverity_desc = (struct code_sign_descriptor *) (sign_data_ptr + sign_block->code_signing_block_hdr.offset
														+ sizeof(tl_header_t) + sign_block->merkle_tree_hdr.length
														+ sizeof(tl_header_t));
	return 0;
}

static int validate_elf_source(const struct code_sign_descriptor *desc)
{
	const u32 sig_size = le32_to_cpu(desc->sig_size);
	int ret = 0;

	code_sign_verify_certchain(desc->signature, sig_size, NULL, &ret);
	if (ret < 0)
		return ret;

	if (ret <= DEBUG_CODE_START || ret >= DEBUG_CODE_END || ret == DEBUG_DEVELOPER_CODE) {
		code_sign_log_error("invalid elf source, type: %d", ret);
		return -EKEYREJECTED;
	}
	return 0;
}

static int enable_by_sign_head(struct file *fp, struct inode *inode, long long fsize, char *sign_head_ptr)
{
	sign_block_t sign_block;
	memset(&sign_block, 0, sizeof(sign_block));

	parse_sign_head(&sign_block.sign_head, sign_head_ptr);
	loff_t sign_data_start = fsize - SIGN_HEAD_SIZE - sign_block.sign_head.sign_data_size;

	/* parse code signing block header */
	char *sign_data_ptr = kzalloc(sign_block.sign_head.sign_data_size, GFP_KERNEL);
	if (!sign_data_ptr) {
		code_sign_log_error("kzalloc of sign_data_ptr failed");
		return -ENOMEM;
	}
	ssize_t cnt = vfs_read(fp, sign_data_ptr, sign_block.sign_head.sign_data_size, &sign_data_start);
	if (cnt != sign_block.sign_head.sign_data_size) {
		code_sign_log_error("read sign data from file failed: read value %lu, expect %u bytes",
							 cnt, sign_block.sign_head.sign_data_size);
		goto out;
	}
	int err = get_block_headers(&sign_block, sign_data_ptr);
	if (err) {
		code_sign_log_error("get_block_headers failed, err: %d", err);
		goto out;
	}

	err = get_merkle_tree(&sign_block, sign_data_ptr);
	if (err) {
		code_sign_log_error("get_merkle_tree failed, err: %d", err);
		goto out;
	}

	/* compute length of padding before merkle tree data */
	merkle_tree_t merkle_tree;
	merkle_tree.padding_length = sign_block.merkle_tree_hdr.length & ((1 << PAGE_SIZE_4K) - 1);
	merkle_tree.merkle_tree_data = sign_data_ptr + sign_block.code_signing_block_hdr.offset
									+ sizeof(tl_header_t) + merkle_tree.padding_length;
	merkle_tree.merkle_tree_length = sign_block.merkle_tree_hdr.length - merkle_tree.padding_length;
	sign_block.merkle_tree = &merkle_tree;

	err = get_fsverity_desc(&sign_block, sign_data_ptr);
	if (err) {
		code_sign_log_error("get_fsverity_desc failed, err: %d", err);
		goto out;
	}

	err = mnt_want_write_file(fp);
	if (err) /* -EROFS */
		goto out;

	err = deny_write_access(fp);
	if (err) /* -ETXTBSY */
		goto out_drop_write;

	/* validate cert chain of elf signer */
	err = validate_elf_source(sign_block.fsverity_desc);
	if (err)
		goto out;

	/* fsverity_enable_with_descriptor in fs/verity/enable.c */
	err = fsverity_enable_with_descriptor(fp, (void *)(sign_block.fsverity_desc), sign_block.fsverity_desc_hdr.length);
	if (err) {
		code_sign_log_error("fsverity_enable_with_descriptor returns err: %d", err);
		goto out_allow_write_access;
	}

	filemap_write_and_wait(inode->i_mapping);
	invalidate_inode_pages2(inode->i_mapping);

out_allow_write_access:
	allow_write_access(fp);
out_drop_write:
	mnt_drop_write_file(fp);
out:
	kfree(sign_data_ptr);
	return err;
}

int elf_file_enable_fs_verity(struct file *file)
{
#ifdef CONFIG_SECURITY_XPM
	/* developer mode */
	if (get_developer_mode_state() != STATE_ON) {
		code_sign_log_info("developer mode off, elf not allowed to execute");
		return -EINVAL;
	}
#else
	code_sign_log_info("developer mode off, elf not allowed to execute");
	return -EINVAL;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	mm_segment_t fs;
#endif
	char *path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf) {
		code_sign_log_error("alloc mem for path_buf failed");
		return -ENOMEM;
	}
	int err = 0;
	char *real_path = file_path(file, path_buf, PATH_MAX - 1);
	if (IS_ERR_OR_NULL(real_path)) {
		code_sign_log_error("get file path failed");
		err = -ENOENT;
		goto release_path_buf_out;
	}

	struct file *fp = filp_open(real_path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		code_sign_log_error("filp_open failed");
		err = PTR_ERR(fp);
		goto release_path_buf_out;
	}
	struct inode *inode = file_inode(fp);
	if (!inode) {
		code_sign_log_error("file_inode failed");
		err = -EFAULT;
		goto filp_close_out;;
	}

	long long fsize = inode->i_size;
	long long pos = 0;
	if (fsize <= SIGN_HEAD_SIZE) {
		code_sign_log_error("file size too small: %llu", fsize);
		err = -EINVAL;
		goto filp_close_out;
	} else {
		pos = fsize - SIGN_HEAD_SIZE;
	}

	char *sign_head_ptr = kzalloc(SIGN_HEAD_SIZE, GFP_KERNEL);
	if (!sign_head_ptr) {
		code_sign_log_error("kzalloc of sign_head_ptr failed");
		err = -ENOMEM;
		goto filp_close_out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	ssize_t cnt = vfs_read(fp, sign_head_ptr, SIGN_HEAD_SIZE, &pos);
	if (cnt != SIGN_HEAD_SIZE) {
		code_sign_log_error("read sign head from file failed: return value %lu, expect %u bytes",
							 cnt, SIGN_HEAD_SIZE);
		err = -EFAULT;
		goto release_sign_head_out;
	}
	sign_head_t *tmp_sign_head = (sign_head_t *)sign_head_ptr;

	/* check magic string */
	if (strncmp(tmp_sign_head->magic, SIGN_MAGIC_STR, sizeof(SIGN_MAGIC_STR) - 1) != 0) {
		err = -EINVAL;
		goto release_sign_head_out;
	}
	if (fsize < (SIGN_HEAD_SIZE + le32_to_cpu(tmp_sign_head->sign_data_size))) {
		code_sign_log_error("sign data size invalid: %u", tmp_sign_head->sign_data_size);
		err = -EINVAL;
		goto release_sign_head_out;
	}

	err = enable_by_sign_head(fp, inode, fsize, sign_head_ptr);
	if (err) {
		code_sign_log_error("enable_by_sign_head err: %d", err);
		goto release_sign_head_out;
	}
	code_sign_log_info("enable fsverity on file %s success", real_path);

release_sign_head_out:
	kfree(sign_head_ptr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	set_fs(fs);
#endif
filp_close_out:
	filp_close(fp, NULL);
release_path_buf_out:
	kfree(path_buf);
	return err;
}

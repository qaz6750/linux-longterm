// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/code_sign.h>
#include <linux/fsverity.h>
#include <linux/stringhash.h>

#include "code_sign_ext.h"
#include "code_sign_log.h"

static time64_t cs_salt;

/**
 * Validate code sign descriptor
 *
 * Return: 1 on code sign version, 0 on basic version, and -errno on failure
 */
static inline int check_code_sign_descriptor(const struct inode *inode,
	const struct code_sign_descriptor *desc)
{
	u64 tree_offset = le64_to_cpu(desc->tree_offset);

	if (!desc->cs_version)
		return 0;
	
	// when calc pgtypeinfo_size, trans bit size to byte size
	u32 pgtypeinfo_size_bytes = le32_to_cpu(desc->pgtypeinfo_size) / 8;
	if (le64_to_cpu(desc->pgtypeinfo_off) > le64_to_cpu(desc->data_size) - pgtypeinfo_size_bytes) {
		code_sign_log_error("Wrong offset: %llu (pgtypeinfo_off) > %llu (data_size) - %u (pgtypeinfo_size)",
				le64_to_cpu(desc->pgtypeinfo_off), le64_to_cpu(desc->data_size), pgtypeinfo_size_bytes);
		return -EINVAL;
	}

	if (le64_to_cpu(desc->data_size) > inode->i_size) {
		code_sign_log_error("Wrong data_size: %llu (desc) > %lld (inode)",
				le64_to_cpu(desc->data_size), inode->i_size);
		return -EINVAL;
	}

	if (desc->salt_size > sizeof(desc->salt)) {
		code_sign_log_error("Invalid salt_size: %u", desc->salt_size);
		return -EINVAL;
	}

	if (IS_INSIDE_TREE(desc)) {
		if ((tree_offset > inode->i_size) || (tree_offset % PAGE_SIZE != 0)) {
			code_sign_log_error(
				"Wrong tree_offset: %llu (desc) > %lld (file size) or alignment is wrong",
					tree_offset, inode->i_size);
			return -EINVAL;
		}
	} else {
		if (tree_offset != 0) {
			code_sign_log_error(
					"Wrong tree_offset without tree: %llu (desc) != 0",
					tree_offset);
			return -EINVAL;
		}
	}
	return 1;
}

void code_sign_check_descriptor(const struct inode *inode, const void *desc, int *ret)
{
	*ret = check_code_sign_descriptor(inode, CONST_CAST_CODE_SIGN_DESC(desc));
}

void code_sign_before_measurement(void *_desc, int *ret)
{
	struct code_sign_descriptor *desc = CAST_CODE_SIGN_DESC(_desc);

	if (desc->cs_version == 1) {
		*ret = desc->cs_version;
		desc->cs_version = 0;
	} else {
		*ret = desc->cs_version;
	}
}

void code_sign_after_measurement(void *_desc, int version)
{
	struct code_sign_descriptor *desc = CAST_CODE_SIGN_DESC(_desc);

	if (version == 1) {
		// restore cs_version
		desc->cs_version = desc->version;
		desc->version = version;
	}
}

void code_sign_init_salt(void)
{
	cs_salt = ktime_get_real_seconds();
}

void code_sign_set_ownerid(struct cs_info *cs_info, uint32_t id_type,
	const char *id_str, uint32_t id_len)
{
	if (!cs_info) {
		code_sign_log_error("Input cs_info is NULL");
		return;
	}

	cs_info->id_type = id_type;
	if (!id_str || id_len == 0)
		cs_info->ownerid = 0;
	else
		cs_info->ownerid = full_name_hash(cs_salt, id_str, id_len);
}
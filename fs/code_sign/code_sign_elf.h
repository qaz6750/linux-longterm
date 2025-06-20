/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CODE_SIGN_ELF_H
#define _CODE_SIGN_ELF_H

#include <linux/fs.h>
#include <linux/code_sign.h>

#define PAGE_SIZE_4K 12

/*
 * Sign block of ELF file consists of
 * sign data and sign head
 *
 * Detailed structure:
 * +-------------------------------------------------+
 * |       |type              (4 bytes)| code signing|
 * |       |length            (4 bytes)| block       |
 * |       |offset            (4 bytes)| header      |
 * |       +---------------------------+-------------|
 * |       |type              (4 bytes)| profile     |
 * |       |length            (4 bytes)| block       |
 * |       |offset            (4 bytes)| header      |
 * |       +---------------------------+-------------|
 * |       | .. other block headers .. |             |
 * |       +---------------------------+-------------|
 * | SIGN  |type              (4 bytes)| merkle      |
 * |       |length            (4 bytes)| tree        |
 * | DATA  |merkle tree data  (N bytes)| block       |
 * |       +---------------------------+-------------|
 * |       |type              (4 bytes)|             |
 * |       |length            (4 bytes)|             |
 * |       |version           (1 byte )|             |
 * |       |hash alg          (1 byte )|             |
 * |       |log2blocksize     (1 byte )|             |
 * |       |salt size         (1 byte )|             |
 * |       |signature size    (4 bytes)|  code sign  |
 * |       |data size         (8 bytes)|  block      |
 * |       |root hash        (64 bytes)|             |
 * |       |salt             (32 bytes)|             |
 * |       |flags             (4 bytes)|             |
 * |       |reserved          (4 bytes)|             |
 * |       |tree offset       (8 bytes)|             |
 * |       |reserved        (127 bytes)|             |
 * |       |cs version        (1 byte )|             |
 * |       |signature         (N bytes)|             |
 * |-------+---------------------------+-------------|
 * |       | magic string    (16 bytes)|             |
 * | SIGN  | version         (4 bytes) |             |
 * |       | sign data size  (4 bytes) |             |
 * | HEAD  | sign block num  (4 bytes) |             |
 * |       | padding         (4 bytes) |             |
 * +-------+-----------------------------------------+
 */

static const __u32 MAGIC_STRING_LEN = 16;
static const char SIGN_MAGIC_STR[] = "elf sign block  ";

enum CODE_SIGNING_DATA_TYPE {
	TYPE_FS_VERITY_DESC = 0x1,
	TYPE_MERKLE_TREE = 0x2
};

enum BLOCK_TYPE {
	BLOCK_TYPE_UNSIGNED_PROFILE = 0x1,
	BLOCK_TYPE_SIGNED_PROFILE = 0x2,
	BLOCK_TYPE_CODE_SIGNING = 0x3
};

#pragma pack(push, 1)
typedef struct
{
	__u8 magic[16];
	__u8 version[4];
	__u32 sign_data_size;
	__u32 sign_block_num;
	__u32 padding;
} sign_head_t;

typedef struct
{
	__u32 type;
	__u32 length;
} tl_header_t;

typedef struct
{
	__u32 type;
	__u32 length;
	__u32 offset;
} block_hdr_t;

#pragma pack(pop)

typedef struct
{
	__u32 padding_length;
	char *merkle_tree_data;
	__u32 merkle_tree_length;
} merkle_tree_t;

typedef struct
{
	/* sign data */
	block_hdr_t code_signing_block_hdr;
	block_hdr_t profile_block_hdr;
	/* code signing block */
	tl_header_t merkle_tree_hdr;
	merkle_tree_t *merkle_tree;
	tl_header_t fsverity_desc_hdr;
	struct code_sign_descriptor *fsverity_desc;

	/* sign head */
	sign_head_t sign_head;
} sign_block_t;

int elf_file_enable_fs_verity(struct file *file);

#endif /* _CODE_SIGN_ELF_H */

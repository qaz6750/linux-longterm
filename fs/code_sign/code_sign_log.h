// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CODE_SIGN_LOG_H
#define _CODE_SIGN_LOG_H

#define CODE_SIGN_TAG "code_sign_kernel"
#define CODE_SIGN_DEBUG_TAG  "D"
#define CODE_SIGN_INFO_TAG  "I"
#define CODE_SIGN_ERROR_TAG "E"
#define CODE_SIGN_WARN_TAG "W"

#define code_sign_log_debug(fmt, args...) pr_debug("[%s/%s]%s: " fmt "\n", \
	CODE_SIGN_DEBUG_TAG, CODE_SIGN_TAG, __func__, ##args)

#define code_sign_log_info(fmt, args...) pr_info("[%s/%s]%s: " fmt "\n", \
	CODE_SIGN_INFO_TAG, CODE_SIGN_TAG, __func__, ##args)

#define code_sign_log_error(fmt, args...) pr_err("[%s/%s]%s: " fmt "\n", \
	CODE_SIGN_ERROR_TAG, CODE_SIGN_TAG, __func__, ##args)

#define code_sign_log_warn(fmt, args...) pr_warn("[%s/%s]%s: " fmt "\n", \
	CODE_SIGN_WARN_TAG, CODE_SIGN_TAG, __func__, ##args)

#endif /* _CODE_SIGN_LOG_H */
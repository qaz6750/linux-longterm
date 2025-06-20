// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/hck/lite_hck_code_sign.h>

#include "code_sign_ioctl.h"
#include "code_sign_log.h"
#include "code_sign_ext.h"

static const struct file_operations code_sign_ops = {
	.owner = THIS_MODULE,
	.open = code_sign_open,
	.release = code_sign_release,
	.unlocked_ioctl = code_sign_ioctl,
	.compat_ioctl = code_sign_ioctl,
};

static struct miscdevice code_sign_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "code_sign",
	.fops = &code_sign_ops,
};

static void code_sign_register_hck_hooks(void)
{
	REGISTER_HCK_LITE_HOOK(code_sign_verify_certchain_lhck, code_sign_verify_certchain);
	REGISTER_HCK_LITE_HOOK(code_sign_check_descriptor_lhck, code_sign_check_descriptor);
	REGISTER_HCK_LITE_HOOK(code_sign_before_measurement_lhck, code_sign_before_measurement);
	REGISTER_HCK_LITE_HOOK(code_sign_after_measurement_lhck, code_sign_after_measurement);
}

static int __init code_sign_init(void)
{
	code_sign_log_info("INIT");

	/* init module init real time as salt for ownerid calculate */
	code_sign_init_salt();

	code_sign_register_hck_hooks();
	return misc_register(&code_sign_misc);
}

static void __exit code_sign_exit(void)
{
	misc_deregister(&code_sign_misc);
	code_sign_log_info("EXIT");
}

module_init(code_sign_init);
module_exit(code_sign_exit);

MODULE_LICENSE("GPL");

# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2023 Huawei Device Co., Ltd.
#
obj-$(CONFIG_SECURITY_CODE_SIGN)	+= \
	code_sign_misc.o \
	verify_cert_chain.o \
	code_sign_ioctl.o \
	code_sign_elf.o \
	code_sign_ext.o

ccflags-$(CONFIG_SECURITY_CODE_SIGN) += \
	-I$(srctree)/fs/verity \
	-I$(srctree)/fs/code_sign \
	-I$(srctree)/security/selinux/include \
	-I$(srctree)/security/selinux \
	-I$(srctree)/security/xpm/developer

$(addprefix $(obj)/,$(obj-y)): $(obj)/flask.h

quiet_cmd_flask = GEN $(obj)/flask.h $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/flask.h $(obj)/av_permissions.h

targets += flask.h av_permissions.h
$(obj)/flask.h: $(srctree)/security/selinux/include/classmap.h FORCE
	$(call if_changed,flask)

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2015 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

APP = dpdk-procinfo

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Wno-deprecated-declarations

# all source are stored in SRCS-y

SRCS-y := main.c

include $(RTE_SDK)/mk/rte.app.mk

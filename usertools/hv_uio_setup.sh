#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Microsoft Corporation

module=uio_hv_generic
# Hyper-V network device GUID
net_guid="f8615163-df3e-46c5-913f-f2d2f965ed0e"

if [ $# -ne 1 ]; then
	echo "Usage: $0 ethN"
	exit 1
fi

syspath=/sys/class/net/$1/device
devpath=$(readlink $syspath)
if [ $? -ne 0 ]; then
	echo "$1 no device present"
	exit 1
fi
dev_guid=$(basename $devpath)

driver=$(readlink $syspath/driver)
if [ $? -ne 0 ]; then
	echo "$1 driver not found"
	exit 1
fi
existing=$(basename $driver)

if [ "$existing" != "hv_netvsc" ]; then
	echo "$1 controlled by $existing"
	exit 1
fi

if [ ! -d /sys/module/$module ]; then
    modprobe $module
    echo $net_guid >/sys/bus/vmbus/drivers/uio_hv_generic/new_id
fi

echo $dev_guid > /sys/bus/vmbus/drivers/$existing/unbind
echo $dev_guid > /sys/bus/vmbus/drivers/$module/bind

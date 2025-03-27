#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
# Copyright 2014 Gary Mills
# Copyright 2019 Joyent, Inc.
# Copyright 2020 Peter Tribble.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2025 Michael van der Westhuizen
#

file path=kernel/drv/$(ARCH)/devfdt
file path=kernel/drv/devfdt.conf
dir  path=platform/armv8
dir  path=platform/armv8/kernel
dir  path=platform/armv8/kernel/$(ARCH)
file path=platform/armv8/kernel/$(ARCH)/unix mode=0755 \
    pkg.depend.bypass-generate=dtracestubs
dir  path=platform/armv8/kernel/dacf
dir  path=platform/armv8/kernel/dacf/$(ARCH)
file path=platform/armv8/kernel/dacf/$(ARCH)/consconfig_dacf mode=0755
dir  path=platform/armv8/kernel/drv
dir  path=platform/armv8/kernel/drv/$(ARCH)
file path=platform/armv8/kernel/drv/$(ARCH)/arm_gtmr
file path=platform/armv8/kernel/drv/$(ARCH)/gicthree
file path=platform/armv8/kernel/drv/$(ARCH)/gictwo
file path=platform/armv8/kernel/drv/$(ARCH)/ns16550a
file path=platform/armv8/kernel/drv/$(ARCH)/rootnex
file path=platform/armv8/kernel/drv/$(ARCH)/simple-bus
file path=platform/armv8/kernel/drv/ns16550a.conf
dir  path=platform/armv8/kernel/misc
dir  path=platform/armv8/kernel/misc/$(ARCH)
file path=platform/armv8/kernel/misc/$(ARCH)/gfx_private group=sys mode=0755
file path=platform/armv8/kernel/misc/$(ARCH)/platmod mode=0755
dir  path=platform/armv8/kernel/tod
dir  path=platform/armv8/kernel/tod/$(ARCH)
file path=platform/armv8/kernel/tod/$(ARCH)/pl03one mode=0755
file path=usr/lib/devfsadm/linkmod/SUNW_misc_link_aarch64.so
file path=usr/share/man/man4d/devfdt.4d
file path=usr/share/man/man4d/simple-bus.4d
driver name=arm_gtmr alias=arm,armv8-timer
driver name=devfdt perms="* 0400 root sys"
driver name=gicthree alias=arm,gic-v3
driver name=gictwo \
    alias=arm,cortex-a15-gic \
    alias=arm,gic-400
driver name=ns16550a perms="* 0666 root sys" perms="*,cu 0600 uucp uucp" \
    alias=arm,pl011
driver name=rootnex
driver name=simple-bus

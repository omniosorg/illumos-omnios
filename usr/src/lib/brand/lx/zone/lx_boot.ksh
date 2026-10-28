#!/bin/ksh -p
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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2017 ASS-Einrichtungssysteme GmbH, Inc.
# Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2020 Joyent, Inc.
#
# lx boot script.
#
# The arguments to this script are the zone name and the zonepath.
#

. /usr/lib/brand/shared/common.ksh

ZONENAME=$1
ZONEPATH=$2
ZONEROOT=$ZONEPATH/root

w_missing=$(gettext "Warning: \"%s\" is not installed in the global zone")

arch=`uname -p`
if [ "$arch" = "i386" ]; then
	ARCH32=i86
        ARCH64=amd64
else
        echo "Unsupported architecture: $arch"
        exit 2
fi

#
# Run the lx_support boot hook.
#
/usr/lib/brand/lx/lx_support boot $ZONEPATH $ZONENAME
if (( $? != 0 )) ; then
        exit 1
fi

BRANDDIR=/native/usr/lib/brand/lx;
EXIT_CODE=1

#
# Before we boot we validate and fix, if necessary, the required files within
# the zone.  These modifications can be lost if a patch or upgrade is applied
# within the zone, so we validate and fix the zone every time it boots.
#

#
# Determine the distro.
#
distro=""
if [[ $(zonecfg -z $ZONENAME info attr name=docker) =~ "value: true" ]]; then
	distro="docker"
elif [[ -f $ZONEROOT/etc/redhat-release ]]; then
	distro="redhat"
elif [[ -f $ZONEROOT/etc/lsb-release ]]; then
	if egrep -s Ubuntu $ZONEROOT/etc/lsb-release; then
		distro="ubuntu"
	elif [[ -f $ZONEROOT/etc/debian_version ]]; then
		distro="debian"
	fi
elif [[ -f $ZONEROOT/etc/debian_version ]]; then
	distro="debian"
elif [[ -f $ZONEROOT/etc/alpine-release ]]; then
	distro="busybox"
elif [[ -f $ZONEROOT/etc/SuSE-release ]]; then
	distro="suse"
elif [[ -f $ZONEROOT/etc/void-release ]]; then
	distro="void"
fi

[[ -z $distro ]] && fatal "Unsupported distribution!"

#
# Retrieve an attribute from the zone configuration
#
zone_attr() {
	zonecfg -z "$ZONENAME" info attr "name=$1" \
	    | nawk '$1 == "value:" {print $2}'
}

#
# Configure common basic network information for an lx zone. This is optionally
# called from the distribution-specific boot script.
#
config_network() {

	################################################################
	# Hostname configuration files within the zone.
	#  /etc/hostname
	[ -s $ZONEROOT/etc/hostname ] || \
	    echo $ZONENAME > $ZONEROOT/etc/hostname

	################################################################
	# Hosts file within the zone.
	#  /etc/hosts
	[ -s $ZONEROOT/etc/hosts ] || \
	    cat <<-EOM > $ZONEROOT/etc/hosts
		# hosts file

		127.0.0.1    localhost $ZONENAME

		# The following lines are desirable for IPv6 capable hosts
		::1     localhost $ZONENAME ip6-localhost ip6-loopback
		ff02::1 ip6-allnodes
		ff02::2 ip6-allrouters

	EOM

	################################################################
	# DNS configuration files within the zone.
	#  /etc/resolv.conf

	typeset domain="`zone_attr dns-domain`"
	typeset resolvers="`zone_attr resolvers`"

	if [ -n "$domain" -o -n "$resolvers" ]; then
		(
			echo "# Auto-generated from zone configuration"
			[ -n "$domain" ] && echo "domain $domain"
			_IFS=$IFS; IFS=,; for r in $resolvers; do
				echo "nameserver $r"
			done
			IFS=$_IFS
		) > $ZONEROOT/etc/resolv.conf
	fi
}

#
# systemd treats an empty or "uninitialized" /etc/machine-id as a first boot.
# It then generates a transient ID and relies on systemd-machine-id-commit,
# which needs mount namespaces, to save it later. That cannot work in an lx
# zone, so every boot would be a first boot. Seed a random ID instead. The
# zone is not running yet, so nothing can replace the file while we work.
#
seed_machine_id() {
	typeset fnm=$ZONEROOT/etc/machine-id
	typeset id tmpfile

	safe_dir /etc
	[[ -f $fnm && ! -h $fnm ]] || return
	id=$(<$fnm)
	[[ -z $id || $id == uninitialized ]] || return

	tmpfile=$(mktemp) || return
	od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > $tmpfile
	echo >> $tmpfile
	chmod 0444 $tmpfile
	mv -f $tmpfile $fnm || rm -f $tmpfile
}

seed_machine_id

#
# Perform distro-specific customization.
#
. $(dirname $0)/lx_boot_zone_${distro}

exit 0

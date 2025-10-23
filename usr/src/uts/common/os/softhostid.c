/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/smbios.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/types.h>

extern int32_t mach_ephemeral_hostid(void);

static char hostid_file[] = "/etc/hostid";

/*
 * On platforms that do not have a hardware serial number, attempt
 * to set one based on the contents of /etc/hostid.  If this file does
 * not exist, assume that we are to generate a new hostid and set
 * it in the kernel, for subsequent saving by a userland process
 * once the system is up and the root filesystem is mounted r/w.
 *
 * In order to gracefully support upgrade on OpenSolaris, if
 * /etc/hostid does not exist, we will attempt to get a serial number
 * using the legacy method (/kernel/misc/sysinit).
 *
 * If that isn't present, we attempt to use an SMBIOS UUID, which is
 * a hardware serial number.  Note that we don't automatically trust
 * all SMBIOS UUIDs (some older platforms are defective and ship duplicate
 * UUIDs in violation of the standard), we check against a blacklist.
 *
 * In an attempt to make the hostid less prone to abuse
 * (for license circumvention, etc), we store it in /etc/hostid
 * in rot47 format.
 */
static int atoi(char *);

/*
 * Set this to non-zero in /etc/system if you think your SMBIOS returns a
 * UUID that is not unique. (Also report it so that the smbios_uuid_blacklist
 * array can be updated.)
 */
int smbios_broken_uuid = 0;

/*
 * List of known bad UUIDs.  This is just the lower 32-bit values, since
 * that's what we use for the host id.  If your hostid falls here, you need
 * to contact your hardware OEM for a fix for your BIOS.
 */

#define	UUID_BLACKLIST_BYTES	16

static uint8_t
smbios_uuid_blacklist[][UUID_BLACKLIST_BYTES] = {

	{	/* Reported bad UUID (Google search) */
		0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
		0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09,
	},
	{	/* Known bad DELL UUID */
		0x4C, 0x4C, 0x45, 0x44, 0x00, 0x00, 0x20, 0x10,
		0x80, 0x20, 0x80, 0xC0, 0x4F, 0x20, 0x20, 0x20,
	},
	{	/* Uninitialized flash */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	},
	{	/* All zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
};

static int32_t
uuid_to_hostid(const uint8_t *uuid)
{
	/*
	 * Although the UUIDs are 128-bits, they may not distribute entropy
	 * evenly.  We would like to use SHA or MD5, but those are located
	 * in loadable modules and not available this early in boot.  As we
	 * don't need the values to be cryptographically strong, we just
	 * generate 32-bit vaue by xor'ing the various sequences together,
	 * which ensures that the entire UUID contributes to the hostid.
	 */
	uint32_t	id = 0;

	/* first check against the blacklist */
	for (int i = 0; i < ARRAY_SIZE(smbios_uuid_blacklist); i++) {
		if (bcmp(smbios_uuid_blacklist[i], uuid,
		    UUID_BLACKLIST_BYTES) == 0) {
			cmn_err(CE_NOTE, "?Broken SMBIOS UUID. "
			    "Contact system firmware vendor for repair.");
			return ((int32_t)HW_INVALID_HOSTID);
		}
	}

	for (int i = 0; i < UUID_BLACKLIST_BYTES; i++)
		id ^= ((uuid[i]) << (8 * (i % sizeof (id))));

	/* Make sure return value is positive */
	return (id & 0x7fffffff);
}

/*
 * Initialize the system hostid in software, for systems without a Sun-like
 * IDPROM.
 */
int32_t
soft_hostid(void)
{
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	int done = 0;
	u_longlong_t tmp;
	int i;
	int32_t hostid = (int32_t)HW_INVALID_HOSTID;
	unsigned char *c;
	smbios_system_t smsys;

	if ((file = kobj_open_file(hostid_file)) == (struct _buf *)-1) {
		/*
		 * hostid file not found - try to load sysinit module
		 * and see if it has a nonzero hostid value.
		 */
		if ((i = modload("misc", "sysinit")) != -1) {
			if (strlen(hw_serial) > 0)
				hostid = (int32_t)atoi(hw_serial);
			(void) modunload(i);
		}

		/*
		 * Use a value derived from the SMBIOS UUID. But not if it is
		 * blacklisted.
		 */
		if ((hostid == HW_INVALID_HOSTID) &&
		    (smbios_broken_uuid == 0) &&
		    (ksmbios != NULL) &&
		    (smbios_info_system(ksmbios, &smsys) != SMB_ERR) &&
		    (smsys.smbs_uuidlen >= 16)) {
			hostid = uuid_to_hostid(smsys.smbs_uuid);
		}

		/*
		 * Generate a "random" hostid using the clock.  These
		 * hostids will change on each boot if the value is not
		 * saved to a persistent /etc/hostid file.
		 */
		if (hostid == HW_INVALID_HOSTID) {
			hostid = mach_ephemeral_hostid();
		}
	} else {
		/* hostid file found */
		while (!done) {
			token = kobj_lex(file, tokbuf, sizeof (tokbuf));

			switch (token) {
			case POUND:
				/*
				 * skip comments
				 */
				kobj_find_eol(file);
				break;
			case STRING:
				/*
				 * un-rot47 - obviously this
				 * nonsense is ascii-specific
				 */
				for (c = (unsigned char *)tokbuf;
				    *c != '\0'; c++) {
					*c += 47;
					if (*c > '~')
						*c -= 94;
					else if (*c < '!')
						*c += 94;
				}
				/*
				 * now we should have a real number
				 */

				if (kobj_getvalue(tokbuf, &tmp) != 0)
					kobj_file_err(CE_WARN, file,
					    "Bad value %s for hostid",
					    tokbuf);
				else
					hostid = (int32_t)tmp;

				break;
			case EOF:
				done = 1;
				/* FALLTHROUGH */
			case NEWLINE:
				kobj_newline(file);
				break;
			default:
				break;

			}
		}
		if (hostid == HW_INVALID_HOSTID) /* didn't find a hostid */
			kobj_file_err(CE_WARN, file,
			    "hostid missing or corrupt");

		kobj_close_file(file);
	}

	/*
	 * hostid is now the value read from /etc/hostid, or the
	 * new hostid we generated in this routine or HW_INVALID_HOSTID if not
	 * set.
	 */
	return (hostid);
}

static int
atoi(char *p)
{
	int i = 0;

	while (*p != '\0')
		i = 10 * i + (*p++ - '0');

	return (i);
}

/* BEGIN CSTYLED */
/*	$OpenBSD: if_iwm.c,v 1.419 2025/12/01 16:30:46 stsp Exp $	*/

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* END CSTYLED */

/*
 * Copyright 2026 lex0de <lex0de@tuta.com>
 * Derived from OpenBSD sys/dev/pci/if_iwm.c at
 * 0efabb066d34187a404f31d303b3b97103df1117, BSD licence option.
 * API 36 TLV semantics with checked byte access and no device operations.
 */
#include <sys/types.h>
#include <sys/errno.h>
#include "if_iwmfw.h"

static uint32_t
iwm_fw_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 |
	    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
}

static int
iwm_fw_section(struct iwm_fw_info *fw, uint_t image, const uint8_t *p,
    size_t length)
{
	struct iwm_fw_image *im = &fw->image[image];
	struct iwm_fw_section *s;
	uint32_t offset;

	if (length < 4 || im->count == IWM_FW_SECTIONS)
		return (EINVAL);
	offset = iwm_fw_u32(p);
	length -= 4;
	if (offset != IWM_FW_CPU_SEPARATOR &&
	    offset != IWM_FW_PAGING_SEPARATOR &&
	    (length == 0 || length > 320 * 1024 || (offset & 3) != 0 ||
	    length - 1 > 0xffffffffU - offset))
		return (EINVAL);
	s = &im->section[im->count++];
	s->offset = offset;
	s->length = length;
	s->data = p + 4;
	return (0);
}

/*
 * Restrict uploads to the authenticated 8000C INIT layout. Separators carry
 * metadata bytes, not upload data. Paging sections are recorded but INIT
 * does not enable paging. REGULAR has a separate layout check below.
 */
static int
iwm_fw_init_layout(struct iwm_fw_info *fw)
{
	static const uint32_t offsets[] = {
		0x00404000, 0x00800000, 0, 0x00448000, 0x00410000,
		IWM_FW_CPU_SEPARATOR, 0x00405000, 0xc0080000,
		0xc0880000, 0x80458000, IWM_FW_PAGING_SEPARATOR,
		0x00440000, 0x01000000
	};
	struct iwm_fw_image *im = &fw->image[IWM_FW_INIT];
	uint_t i;

	if (im->count != sizeof (offsets) / sizeof (offsets[0]))
		return (EINVAL);
	for (i = 0; i < im->count; i++) {
		if (im->section[i].offset != offsets[i])
			return (EINVAL);
	}
	if (im->section[5].length != 32 || im->section[10].length != 4 ||
	    im->section[12].length != fw->paging_size)
		return (EINVAL);
	return (0);
}

/* REGULAR uses eight upload sections and a bounded host paging image. */
static int
iwm_fw_regular_layout(struct iwm_fw_info *fw)
{
	static const uint32_t offsets[] = {
		0x00404000, 0x00800000, 0, 0x00448000,
		IWM_FW_CPU_SEPARATOR, 0x00405000, 0xc0080000,
		0xc0880000, 0x80458000, IWM_FW_PAGING_SEPARATOR,
		0x00440000, 0x01000000
	};
	struct iwm_fw_image *im = &fw->image[IWM_FW_REGULAR];
	uint_t i;

	if (im->count != sizeof (offsets) / sizeof (offsets[0]))
		return (EINVAL);
	for (i = 0; i < im->count; i++) {
		if (im->section[i].offset != offsets[i])
			return (EINVAL);
	}
	if (im->section[4].length != 32 || im->section[9].length != 4 ||
	    im->section[10].length > 4096 || fw->paging_size == 0 ||
	    im->section[11].length != fw->paging_size)
		return (EINVAL);
	return (0);
}

/*
 * Caller owns immutable data/size and supplies zeroed metadata. Pointers in
 * the result borrow that image until it is freed. A nonzero return invalidates
 * all parsed metadata: no caller may upload any section after failure.
 */
int
iwm_fw_parse(struct iwm_fw_info *fw)
{
	const uint8_t *p = fw->data;
	size_t left = fw->size;
	uint32_t type, len, index;
	uint_t i;
	int error;
	boolean_t version = B_FALSE, phy = B_FALSE, commands = B_FALSE;

	if (p == 0 || left < 88 || left > 4 * 1024 * 1024 ||
	    iwm_fw_u32(p) != 0 || iwm_fw_u32(p + 4) != 0x0a4c5749)
		return (EINVAL);
	p += 88;
	left -= 88;
	while (left != 0) {
		if (left < 8)
			return (EINVAL);
		type = iwm_fw_u32(p);
		len = iwm_fw_u32(p + 4);
		p += 8;
		left -= 8;
		if (len > left)
			return (EINVAL);
		switch (type) {
		case 19: /* SEC_RT */
		case 20: /* SEC_INIT */
		case 21: /* SEC_WOWLAN: metadata only. */
			error = iwm_fw_section(fw, type - 19, p, len);
			if (error != 0)
				return (error);
			break;
		case 6: /* PROBE_MAX_LEN */
			if (len < 4 || iwm_fw_u32(p) > 512)
				return (EINVAL);
			break;
		case 7: /* PAN */
			if (len != 0)
				return (EINVAL);
			fw->flags |= 1;
			break;
		case 18: /* FLAGS, donor consumes the first word. */
			if (len < 4)
				return (EINVAL);
			fw->flags = iwm_fw_u32(p);
			break;
		case 22: /* DEF_CALIB, per-image firmware calibration masks. */
			if (len != 12 ||
			    (index = iwm_fw_u32(p)) >= IWM_FW_IMAGES ||
			    fw->image[index].calib_valid)
				return (EINVAL);
			fw->image[index].calib_flow = iwm_fw_u32(p + 4);
			fw->image[index].calib_event = iwm_fw_u32(p + 8);
			fw->image[index].calib_valid = B_TRUE;
			break;
		case 23: /* PHY_SKU */
			if (len != 4 || phy)
				return (EINVAL);
			fw->phy_config = iwm_fw_u32(p);
			phy = B_TRUE;
			break;
		case 27: /* NUM_OF_CPU */
			if (len != 4 || fw->cpu_count != 0 ||
			    iwm_fw_u32(p) != 2)
				return (EINVAL);
			fw->cpu_count = 2;
			break;
		case 28: /* CSCHEME: validate storage, do not choose crypto. */
			if (len < 1 || p[0] > (len - 1) / 13)
				return (EINVAL);
			break;
		case 29: /* API_CHANGES_SET */
		case 30: /* ENABLED_CAPABILITIES */
			if (len != 8 || (index = iwm_fw_u32(p)) >= 4)
				return (EINVAL);
			if (type == 29)
				fw->api[index] |= iwm_fw_u32(p + 4);
			else
				fw->capa[index] |= iwm_fw_u32(p + 4);
			break;
		case 31: /* N_SCAN_CHANNELS */
			if (len != 4 || iwm_fw_u32(p) > 52)
				return (EINVAL);
			fw->scan_channels = iwm_fw_u32(p);
			break;
		case 32: /* PAGING, retained but not activated for INIT. */
			if (len != 4 || iwm_fw_u32(p) > 1024 * 1024 ||
			    (iwm_fw_u32(p) & 4095) != 0)
				return (EINVAL);
			fw->paging_size = iwm_fw_u32(p);
			break;
		case 36: /* FW_VERSION */
			if (len != 12 || version)
				return (EINVAL);
			for (i = 0; i < 3; i++)
				fw->version[i] = iwm_fw_u32(p + 4 * i);
			version = B_TRUE;
			break;
		case 48: /* CMD_VERSIONS */
			if (commands || len % 4 != 0 ||
			    len > sizeof (fw->cmd_versions))
				return (EINVAL);
			for (i = 0; i < len; i++)
				fw->cmd_versions[i] = p[i];
			fw->cmd_version_count = len / 4;
			commands = B_TRUE;
			break;
		case 35: /* SDIO_ADMA_ADDR */
		case 50: /* FW_GSCAN_CAPA */
		case 51: /* FW_MEM_SEG */
			break; /* Unused by the pinned donor's PCI INIT path. */
		default:
			return (ENOTSUP);
		}
		p += len;
		left -= len;
		/* The donor accepts absent padding only at end of the file. */
		index = (4 - (len & 3)) & 3;
		if (left < index) {
			if (left != 0)
				return (EINVAL);
			break;
		}
		p += index;
		left -= index;
	}
	if (!version || !phy || !commands || fw->cpu_count != 2 ||
	    fw->version[0] != 36 || fw->version[1] != 0xca7b901d ||
	    fw->version[2] != 0)
		return (EINVAL);
	if (!fw->image[IWM_FW_INIT].calib_valid ||
	    !fw->image[IWM_FW_REGULAR].calib_valid)
		return (EINVAL);
	if ((error = iwm_fw_init_layout(fw)) != 0)
		return (error);
	return (iwm_fw_regular_layout(fw));
}

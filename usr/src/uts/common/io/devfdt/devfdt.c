/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Richard Lowe
 */

/*
 * /dev/fdt -- a character device exposing the Flat Device Tree blob
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>

#include <libfdt.h>

extern const struct fdt_header *prom_get_fdtp(void);

/*
 * We don't do any snapshotting or reference counting.  If the FDT should
 * become in anyway dynamic, this will require at least the former.
 */
static int
devfdt_open(dev_t *dip, int flag, int otyp, cred_t *cred)
{
	const struct fdt_header *fdtp = prom_get_fdtp();

	ASSERT3P(fdtp, !=, NULL);

	/*
	 * It would be nice even if the fdt is bogus if we could present it to
	 * userland to look at.  Unfortunately we have to trust the length in
	 * the header to validate reads, and so this is necessary defensively.
	 *
	 * Perhaps it's for the best.
	 */
	if (fdt_check_header(fdtp) != 0)
		return (EPROTO);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	return (0);
}

static int
devfdt_read(dev_t dev, uio_t *uio, cred_t *cred)
{
	const struct fdt_header *fdtp = prom_get_fdtp();

	ASSERT3P(fdtp, !=, NULL);

	size_t fdtlen = fdt_totalsize(fdtp);

	if (uio->uio_offset < 0 || uio->uio_offset > fdtlen) {
		cmn_err(CE_WARN, "fdt: bad read offset");
		return (0);
	}

	int len = uio->uio_resid;

	if (uio->uio_offset + len > fdtlen)
		len = fdtlen - uio->uio_offset;

	return (uiomove(((caddr_t)fdtp + uio->uio_offset),
	    MIN(len, fdtlen - uio->uio_offset), UIO_READ, uio));
}

static int
devfdt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	const struct fdt_header *fdtp = prom_get_fdtp();

	if (fdtp == NULL)
		return (DDI_FAILURE);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "fdt",
	    S_IFCHR, 0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	ddi_prop_update_int64(0, dip, "Size", fdt_totalsize(fdtp));

	return (DDI_SUCCESS);
}

static int
devfdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

static struct cb_ops devfdt_cb_ops = {
	.cb_open = devfdt_open,
	.cb_close = nulldev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = devfdt_read,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_NEW | D_MP,
};

static struct dev_ops devfdt_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = devfdt_attach,
	.devo_detach = devfdt_detach,
	.devo_cb_ops = &devfdt_cb_ops,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Flat Device Tree device driver",
	.drv_dev_ops = &devfdt_ops
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modldrv, NULL },
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modlinkage, modinfo));
}

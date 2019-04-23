/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, 2015 by Delphix. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 * Copyright (c) 2016 Martin Matuska. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include "ndmpd.h"
#include <libzfs.h>

/*
 * Put a hold on snapshot
 */
int
snapshot_hold(char *volname, char *snapname, char *jname)
{
	zfs_handle_t *zhp;
	char *p;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		syslog(LOG_ERR, "Cannot open volume %s.", volname);
		return (-1);
	}
	p = strchr(snapname, '@') + 1;
	/*
	 * The -1 tells the lower levels there are no snapshots
	 * to clean up.
	 */
	if (zfs_hold(zhp, p, jname, B_FALSE, -1) != 0) {
		syslog(LOG_ERR, "Cannot hold snapshot %s", p);
		zfs_close(zhp);
		return (-1);
	}
	zfs_close(zhp);
	return (0);
}

int
snapshot_release(char *volname, char *snapname, char *jname)
{
	zfs_handle_t *zhp;
	char *p;
	int rv = 0;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		syslog(LOG_ERR, "Cannot open volume %s", volname);
		return (-1);
	}

	p = strchr(snapname, '@') + 1;
	if (zfs_release(zhp, p, jname, B_FALSE) != 0) {
		syslog(LOG_DEBUG, "Cannot release snapshot %s", p);
		rv = -1;
	}
	zfs_close(zhp);
	return (rv);
}

/*
 * Create a snapshot, put a hold on it, clone it, and mount it in a
 * well known location for so the backup process can traverse its
 * directory tree structure.
 */
int
backup_dataset_create(ndmp_lbr_params_t *nlp)
{
	char zpoolname[ZFS_MAX_DATASET_NAME_LEN];
	char *slash;
	int rv;

	if (nlp == NULL) {
		return (-1);
	}

	(void) strlcpy(zpoolname, nlp->nlp_vol, sizeof (zpoolname));
	/*
	 * Pull out the pool name component from the volname
	 * to use it to build snapshot and clone names.
	 */
	slash = strchr(zpoolname, '/');
	if (slash != NULL) {
		*slash = '\0';
	}

	(void) snprintf(nlp->nlp_clonename, sizeof (nlp->nlp_clonename),
	    "%s/%s", zpoolname, nlp->nlp_job_name);

	(void) mutex_lock(&zlib_mtx);

	/*
	 * If "checkpoint" is not enabled, create the normal
	 * snapshot and continue normal backup.  If it is
	 * enabled, the "checkpoint" name has been already set
	 * so we just have to clone it.
	 */
	if (!NLP_ISCHKPNTED(nlp)) {
		(void) snprintf(nlp->nlp_snapname, sizeof (nlp->nlp_snapname),
		    "%s@%s", nlp->nlp_vol, nlp->nlp_job_name);

		if ((rv = zfs_snapshot(zlibh, nlp->nlp_snapname,
		    B_FALSE, NULL)) != 0) {
			if (errno == EEXIST) {
				(void) mutex_unlock(&zlib_mtx);
				return (0);
			}
			syslog(LOG_ERR,
			    "backup_dataset_create: %s failed (err=%d): %s",
			    nlp->nlp_snapname, errno,
			    libzfs_error_description(zlibh));
			(void) mutex_unlock(&zlib_mtx);
			return (rv);
		}
		if (snapshot_hold(nlp->nlp_vol,
		    nlp->nlp_snapname, NDMP_RCF_BASENAME) != 0) {
			syslog(LOG_DEBUG,
			    "backup_dataset_create: %s "
			    "hold failed (err=%d): %s",
			    nlp->nlp_snapname,
			    errno, libzfs_error_description(zlibh));
			(void) mutex_unlock(&zlib_mtx);
			return (-1);
		}
		syslog(LOG_DEBUG,
		    "Using %s NdmpBackup snapshot for backup",
		    nlp->nlp_snapname);

	}

	if (ndmp_clone_snapshot(nlp) != 0) {
		syslog(LOG_ERR,
		    "backup_dataset_create: %s clone failed (err=%d): %s",
		    nlp->nlp_snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}
	(void) mutex_unlock(&zlib_mtx);
	return (0);
}

/*
 * Unmount, release, and destroy the snapshot created for backup.
 */
int
backup_dataset_destroy(ndmp_lbr_params_t *nlp)
{
	char zpoolname[ZFS_MAX_DATASET_NAME_LEN];
	char *slash;
	zfs_handle_t *vol_zhp;
	zfs_handle_t *cln_zhp;
	int err;
	int rv = 0;

	if (nlp == NULL) {
		syslog(LOG_DEBUG,
		    "nlp NULL in backup_dataset_destroy");
		return (-1);
	}

	(void) strlcpy(zpoolname, nlp->nlp_vol, sizeof (zpoolname));
	slash = strchr(zpoolname, '/');
	if (slash != NULL) {
		*slash = '\0';
	}

	if (!NLP_ISCHKPNTED(nlp)) {
		(void) snprintf(nlp->nlp_snapname, sizeof (nlp->nlp_snapname),
		    "%s@%s", nlp->nlp_vol, nlp->nlp_job_name);
	}


	syslog(LOG_DEBUG, "Snapname in backup_dataset_destroy is [%s]",
	    nlp->nlp_snapname);

	/*
	 * Destroy using this sequence
	 * zfs release <volume>@<jname>
	 * zfs destroy <pool>/<jname>
	 * zfs destroy <pool>/<volume>@<jname>
	 */
	(void) mutex_lock(&zlib_mtx);

	/*
	 * Release the normal snapshot but don't try to
	 * release if it's a "checkpoint" because the hold
	 * wasn't put on it to begin with.
	 */
	if (!NLP_ISCHKPNTED(nlp)) {
		if (snapshot_release(nlp->nlp_vol,
		    nlp->nlp_snapname, NDMP_RCF_BASENAME) != 0) {
			syslog(LOG_DEBUG,
			    "backup_dataset_destroy: %s "
			    "release failed (err=%d): %s",
			    nlp->nlp_clonename, errno,
			    libzfs_error_description(zlibh));
			(void) mutex_unlock(&zlib_mtx);
			return (-1);
		}
	} else {
		syslog(LOG_DEBUG, "Checkpointed dataset not held "
		    "will not release [%s]", nlp->nlp_snapname);
	}

	/*
	 * Open the clone to get descriptor
	 */
	if ((cln_zhp = zfs_open(zlibh, nlp->nlp_clonename,
	    ZFS_TYPE_VOLUME | ZFS_TYPE_FILESYSTEM)) == NULL) {
		syslog(LOG_ERR,
		    "backup_dataset_destroy: open %s failed",
		    nlp->nlp_clonename);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	/*
	 * Open the mounted clone to get descriptor for unmount
	 */
	if ((vol_zhp = zfs_open(zlibh, nlp->nlp_vol,
	    ZFS_TYPE_VOLUME | ZFS_TYPE_FILESYSTEM)) == NULL) {
		syslog(LOG_ERR,
		    "backup_dataset_destroy: open %s failed [while trying "
		    "to destroy]", nlp->nlp_vol);
		zfs_close(cln_zhp);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	/*
	 * This unmounts the clone which was just traversed for backup
	 */
	if ((err = zfs_unmount(cln_zhp, NULL, 0)) != 0) {
		syslog(LOG_INFO, "failed to unmount [%s]", nlp->nlp_clonename);
		rv = -1;
		goto _out;
	}

	/*
	 * This destroys the clone
	 */
	err = zfs_destroy(cln_zhp, B_TRUE);
	if (err) {
		syslog(LOG_ERR, "%s destroy: %d; %s; %s",
		    nlp->nlp_clonename,
		    libzfs_errno(zlibh),
		    libzfs_error_action(zlibh),
		    libzfs_error_description(zlibh));
		rv = -1;
		goto _out;
	}

	/*
	 * This destroys the snapshot of the current backup - but,
	 * don't destroy it if it is an "checkpoint" from AutoSync
	 * or HPR.
	 */
	if (!NLP_ISCHKPNTED(nlp)) {
		if ((err = zfs_destroy_snaps(vol_zhp,
		    nlp->nlp_job_name, B_TRUE))) {
			syslog(LOG_ERR, "%s destroy: %d; %s; %s",
			    nlp->nlp_job_name,
			    libzfs_errno(zlibh),
			    libzfs_error_action(zlibh),
			    libzfs_error_description(zlibh));
			rv = -1;
			syslog(LOG_DEBUG, "Destroy [%s]", nlp->nlp_snapname);
			goto _out;
		}
	} else {
		syslog(LOG_DEBUG, "Checkpointed checkpoint will not destroy [%s]",
		    nlp->nlp_snapname);
	}

_out:
	zfs_close(vol_zhp);
	zfs_close(cln_zhp);
	(void) mutex_unlock(&zlib_mtx);

	/*
	 * The zfs_clone() call will have mounted the snapshot
	 * in the file system at this point - so clean it up.
	 */
	if (rv == 0) {
		if (rmdir(nlp->nlp_mountpoint) != 0) {
			syslog(LOG_ERR,
			    "Failed to remove mount point [%s]",
			    nlp->nlp_mountpoint);
			return (-1);
		}
	}

	return (rv);
}

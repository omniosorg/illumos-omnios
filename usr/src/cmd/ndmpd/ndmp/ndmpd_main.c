/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
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
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */

#include <errno.h>
#include <signal.h>
#include <libscf.h>
#include <libintl.h>
#include <sys/wait.h>
#include <syslog.h>
#include <syslog.h>
#include <zone.h>
#include <tsol/label.h>
#include <dlfcn.h>
#include <sys/mount.h>
#include <libzfs.h>
#include "ndmpd.h"
#include "ndmpd_common.h"

/* zfs library handle & mutex */
libzfs_handle_t *zlibh;
mutex_t	zlib_mtx;
void *mod_plp;

static void ndmpd_sig_handler(int sig);

typedef struct ndmpd {
	int s_shutdown_flag;	/* Fields for shutdown control */
	int s_sigval;
} ndmpd_t;

ndmpd_t	ndmpd;


/*
 * Load and initialize the plug-in module
 */
static int
mod_init()
{
	char *plname;
	ndmp_plugin_t *(*plugin_init)(int);

	ndmp_pl = NULL;

	plname = ndmpd_get_prop(NDMP_PLUGIN_PATH);
	if (plname == NULL || *plname == '\0')
		return (0);

	if ((mod_plp = dlopen(plname, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		syslog(LOG_ERR, "Error loading the plug-in %s: %s",
		    plname, dlerror());
		return (0);
	}

	plugin_init = (ndmp_plugin_t *(*)(int))dlsym(mod_plp, "_ndmp_init");
	if (plugin_init == NULL) {
		(void) dlclose(mod_plp);
		return (0);
	}
	if ((ndmp_pl = plugin_init(NDMP_PLUGIN_VERSION)) == NULL) {
		syslog(LOG_ERR, "Error loading the plug-in %s", plname);
		return (-1);
	}
	return (0);
}

/*
 * Unload
 */
static void
mod_fini()
{
	if (ndmp_pl == NULL)
		return;

	void (*plugin_fini)(ndmp_plugin_t *);

	plugin_fini = (void (*)(ndmp_plugin_t *))dlsym(mod_plp, "_ndmp_fini");
	if (plugin_fini == NULL) {
		(void) dlclose(mod_plp);
		return;
	}
	plugin_fini(ndmp_pl);
	(void) dlclose(mod_plp);
}

static void
set_privileges(void)
{
	priv_set_t *pset = priv_allocset();

	/*
	 * Set effective sets privileges to 'least' required. If fails, send
	 * error messages to log file and proceed.
	 */
	if (pset != NULL) {
		priv_basicset(pset);
		(void) priv_addset(pset, PRIV_PROC_AUDIT);
		(void) priv_addset(pset, PRIV_PROC_SETID);
		(void) priv_addset(pset, PRIV_PROC_OWNER);
		(void) priv_addset(pset, PRIV_FILE_CHOWN);
		(void) priv_addset(pset, PRIV_FILE_CHOWN_SELF);
		(void) priv_addset(pset, PRIV_FILE_DAC_READ);
		(void) priv_addset(pset, PRIV_FILE_DAC_SEARCH);
		(void) priv_addset(pset, PRIV_FILE_DAC_WRITE);
		(void) priv_addset(pset, PRIV_FILE_OWNER);
		(void) priv_addset(pset, PRIV_FILE_SETID);
		(void) priv_addset(pset, PRIV_SYS_LINKDIR);
		(void) priv_addset(pset, PRIV_SYS_DEVICES);
		(void) priv_addset(pset, PRIV_SYS_MOUNT);
		(void) priv_addset(pset, PRIV_SYS_CONFIG);
	}

	if (pset == NULL || setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) != 0) {
		(void) fprintf(stderr,
		    "Failed to set least required privileges to the service\n");
	}
	priv_freeset(pset);
}

static void
daemonize_init(void)
{
	sigset_t set, oset;
	pid_t pid;

	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	if ((pid = fork()) == -1) {
		(void) fprintf(stderr,
		    "Failed to start process in background.\n");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* If we're the parent process, exit. */
	if (pid != 0) {
		_exit(0);
	}
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
}

/*
 * Utility routine to check if a zpool is bootable. For the purposes
 * of cleaning up ndmp backup clones and snapshots, shouldn't consider
 * the 'boot' volume.
 *
 * Parameters:
 *   zhp (input) - the zfs handle of the zpool dataset.
 *
 * Returns:
 *   B_TRUE : If the given zpool has a boot record
 *   B_FALSE: otherwise
 */
boolean_t
ndmp_zpool_is_bootable(zpool_handle_t *zhp)
{
	char bootfs[ZFS_MAX_DATASET_NAME_LEN];

	return (zpool_get_prop(zhp, ZPOOL_PROP_BOOTFS, bootfs,
	    sizeof (bootfs), NULL, B_FALSE) == 0 && strncmp(bootfs, "-",
	    sizeof (bootfs)) != 0);
}

/*
 * This is the zpool_iter() callback routine specifically for
 * ZFS_TYPE_SNAPSHOTS and is passed in a zfs handle to each one
 * it finds during iteration.  If this callback returns zero
 * the iterator keeps going, if it returns non-sero the
 * iteration stops.
 *
 * Parameters:
 *   zhp (input) - the zfs handle of the ZFS_TYPE_SNAPSHOTS dataset.
 *   arg (input) - optional parameter (not used in this case)
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
/*ARGSUSED*/
int
ndmp_match_and_destroy_snapshot(zfs_handle_t *zhp, void *arg)
{
	int err = 0;
	char *dataset_name;
	char *snap_name;
	char *snap_delim;
	zfs_handle_t *dszhp;

	dataset_name = strdup(zfs_get_name(zhp));
	if (zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT) {
		if (strstr(dataset_name, NDMP_RCF_BASENAME) != NULL) {
			snap_delim = strchr(dataset_name, '@');
			snap_name = snap_delim + 1;
			*snap_delim = '\0';

			syslog(LOG_DEBUG,
			    "Remove snap [%s] from dataset [%s] tag [%s]\n",
			    snap_name, dataset_name, NDMP_RCF_BASENAME);

			if ((dszhp = zfs_open(zlibh, dataset_name,
			    ZFS_TYPE_DATASET)) != NULL) {
				if ((err = zfs_release(dszhp, snap_name,
				    NDMP_RCF_BASENAME, B_FALSE)) != 0) {
					if (libzfs_errno(zlibh)
					    != EZFS_REFTAG_RELE) {
						syslog(LOG_DEBUG,
						    "(%d) problem zfs_release "
						    "error:%s action:"
						    "%s errno:%d\n",
						    err,
						    libzfs_error_description(
						    zlibh),
						    libzfs_error_action(
						    zlibh),
						    libzfs_errno(
						    zlibh));
						zfs_close(dszhp);
						goto _out;
					}
				}
				if ((err = zfs_destroy(zhp, B_FALSE)) != 0) {
					syslog(LOG_DEBUG,
					    "(%d)snapshot: problem zfs_destroy "
					    "error:%s action:%s errno:%d\n",
					    err,
					    libzfs_error_description(zlibh),
					    libzfs_error_action(zlibh),
					    libzfs_errno(zlibh));
				}
				zfs_close(dszhp);
			} else {
				err = -1;
				goto _out;
			}
		}
	}
_out:
	free(dataset_name);
	zfs_close(zhp);
	return (err);
}

/*
 * This is the zpool_iter() callback routine specifically for
 * ZFS_TYPE_FILESYSTEM and is passed in a zfs handle to each one
 * it finds during iteration.  If this callback returns zero
 * the iterator keeps going, if it returns non-sero the
 * iteration stops.
 *
 * Parameters:
 *   zhp (input) - the zfs handle of the ZFS_TYPE_FILESYSTEM dataset.
 *   arg (input) - optional parameter (not used in this case)
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
/*ARGSUSED*/
int
ndmp_match_and_destroy_filesystem(zfs_handle_t *zhp, void *arg)
{
	int err = 0;
	char *mntpt = NULL;
	char *dataset_name;

	dataset_name = strdup(zfs_get_name(zhp));
	if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM)  {
		if (strstr(dataset_name, NDMP_RCF_BASENAME) != NULL) {

			syslog(LOG_DEBUG,
			    "Remove filesystem [%s]", dataset_name);
			if (zfs_is_mounted(zhp, &mntpt)) {
				syslog(LOG_DEBUG,
				    "mountpoint for snapshot is [%s]\n", mntpt);
				if (zfs_unmount(zhp, NULL, MS_FORCE) != 0) {
					syslog(LOG_DEBUG, "Failed to unmount "
					    "mount point [%s]", mntpt);
					err = -1;
					goto _out;
				}
			}
			if (rmdir(mntpt) != 0) {
				if (errno != ENOENT) {
					syslog(LOG_DEBUG, "Failed to remove "
					    "mount point [%s]", mntpt);
					err = -1;
					goto _out;
				}
			}

			if ((err = zfs_destroy(zhp, B_FALSE)) != 0) {
				syslog(LOG_DEBUG,
				    "(%d)filesystem: problem zfs_destroy "
				    "error:%s action:%s errno:%d\n",
				    err, libzfs_error_description(zlibh),
				    libzfs_error_action(zlibh),
				    libzfs_errno(zlibh));
			}
		}
	}
_out:
	free(dataset_name);
	zfs_close(zhp);
	return (err);
}

/*
 * This is the zpool iterator callback routine.  For each pool on
 * the system iterate filesystem dependents first then iterate snapshot
 * dependents and run the corresponding ndmp_match_and_destroy_XXX()
 * callback. The 'snapshot' are removed second because 'filesystem'
 * is dependend on its parent 'snapshot'.  If this callback returns
 * zero the iterator keeps going, if it returns non-sero the
 * iteration stops.
 *
 * Parameters:
 *   zhp (input) - the zfs handle of the zpool dataset.
 *   arg (input) - optional parameter (not used in this case)
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
/*ARGSUSED*/
int
ndmp_cleanup_snapshots_inpool(zfs_handle_t *zhp, void *arg)
{
	const char *zpool_name;
	int err = 0;
	zpool_handle_t *php;

	/*
	 * Check for pools with bootfs entries and skip them
	 */
	zpool_name = zfs_get_name(zhp);
	if ((php = zpool_open(zlibh, zpool_name)) != NULL) {
		if (!ndmp_zpool_is_bootable(php)) {
			syslog(LOG_DEBUG,
			    "Working on pool [%s]\n", zfs_get_name(zhp));

			err = zfs_iter_dependents(zhp, B_FALSE,
			    ndmp_match_and_destroy_filesystem, (void *)NULL);
			if (err) {
				syslog(LOG_ERR,
				    "cleanup filesystems error: "
				    "%d on pool [%s]",
				    err, zpool_name);
				goto _out;
			}
			err = zfs_iter_dependents(zhp,
			    B_FALSE, ndmp_match_and_destroy_snapshot,
			    (void *)NULL);
			if (err) {
				syslog(LOG_ERR,
				    "cleanup snapshots error: %d on pool",
				    err, zpool_name);
			}
		}
	}
_out:
	zpool_close(php);
	zfs_close(zhp);
	return (err);
}

/*
 * main
 *
 * The main NDMP daemon function
 *
 * Parameters:
 *   argc (input) - the argument count
 *   argv (input) - command line options
 *
 * Returns:
 *   0
 */
int
main(int argc, char *argv[])
{
	struct sigaction act;
	sigset_t set;
	char c;
	void *arg = NULL;
	boolean_t run_in_foreground = B_FALSE;

	/*
	 * Check for existing ndmpd door server (make sure ndmpd is not already
	 * running)
	 */
	if (ndmp_door_check()) {
		/* ndmpd is already running, exit. */
		(void) fprintf(stderr, "ndmpd is already running.\n");
		return (0);
	}

	/* Global zone check */
	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr, "Non-global zone not supported.\n");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* Trusted Solaris check */
	if (is_system_labeled()) {
		(void) fprintf(stderr, "Trusted Solaris not supported.\n");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* load SMF configuration */
	if (ndmpd_load_prop()) {
		(void) fprintf(stderr,
		    "SMF properties initialization failed.\n");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	opterr = 0;
	while ((c = getopt(argc, argv, "df")) != -1) {
		switch (c) {
		case 'f':
			run_in_foreground = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, "%s: Invalid option -%c.\n",
			    argv[0], optopt);
			(void) fprintf(stderr, "Usage: %s [-f]\n", argv[0]);
			exit(SMF_EXIT_ERR_CONFIG);
		}
	}

	/* set up signal handler */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT); /* always unblocked for ASSERT() */
	(void) sigfillset(&act.sa_mask);
	act.sa_handler = ndmpd_sig_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGUSR1, &act, NULL);
	(void) sigaction(SIGPIPE, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGUSR1);
	(void) sigdelset(&set, SIGPIPE);

	set_privileges();
	(void) umask(077);
	openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_LOCAL4);

	if (!run_in_foreground)
		daemonize_init();

	if (mod_init() != 0) {
		syslog(LOG_ERR, "Failed to load the plugin module.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* libzfs init */
	if ((zlibh = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "Failed to initialize ZFS library.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* initialize and start the door server */
	if (ndmp_door_init()) {
		syslog(LOG_ERR, "Can not start ndmpd door server.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	if (tlm_init() == -1) {
		syslog(LOG_ERR, "Failed to initialize tape manager.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Use libzfs iterator routine to list through all the pools and
	 * invoke cleanup callback routine on each.
	 */
	if (zfs_iter_root(zlibh,
	    ndmp_cleanup_snapshots_inpool, (void *)NULL) != 0) {
		syslog(LOG_ERR, "Failed to cleanup leftover snapshots.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/*
	 * Prior to this point, we are single-threaded. We will be
	 * multi-threaded from this point on.
	 */
	(void) pthread_create(NULL, NULL, (funct_t)ndmpd_main,
	    (void *)&arg);

	while (!ndmpd.s_shutdown_flag) {
		(void) sigsuspend(&set);

		switch (ndmpd.s_sigval) {
		case 0:
			break;

		case SIGPIPE:
			break;

		case SIGHUP:
			/* Refresh SMF properties */
			if (ndmpd_load_prop())
				syslog(LOG_ERR,
				    "Service properties initialization "
				    "failed.");
			break;

		default:
			/*
			 * Typically SIGINT or SIGTERM.
			 */
			ndmpd.s_shutdown_flag = 1;
			break;
		}

		ndmpd.s_sigval = 0;
	}

	libzfs_fini(zlibh);
	mod_fini();
	ndmp_door_fini();
	closelog();

	return (SMF_EXIT_OK);
}

static void
ndmpd_sig_handler(int sig)
{
	if (ndmpd.s_sigval == 0)
		ndmpd.s_sigval = sig;
}

/*
 * Enable libumem debugging by default on DEBUG builds.
 */
#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif

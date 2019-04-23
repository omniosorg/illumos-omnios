/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
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
/* Copyright 2017 Nexenta Systems, Inc. All rights reserved. */

/*
 * This file implemets the post-order, pre-order and level-order
 * traversing of the file system.  The related macros and constants
 * are defined in traverse.h.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <cstack.h>
#include <dirent.h>
#include <errno.h>
#include <traverse.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <tlm.h>
#include "tlm_proto.h"

/*
 * Check if it's "." or ".."
 */
boolean_t
rootfs_dot_or_dotdot(char *name)
{
	if (*name != '.')
		return (FALSE);

	if ((name[1] == 0) || (name[1] == '.' && name[2] == 0))
		return (TRUE);

	return (FALSE);
}

/*
 * Macros on fs_traverse flags.
 */
#define	STOP_ONERR(f)	((f)->ft_flags & FST_STOP_ONERR)
#define	STOP_ONLONG(f)	((f)->ft_flags & FST_STOP_ONLONG)

#define	CALLBACK(pp, ep)	\
	(*(ftp)->ft_callbk)((ftp)->ft_arg, pp, ep)

#define	NEGATE(rv)	((rv) =	-(rv))

/*
 * The traversing state that is pushed onto the stack.
 * This include:
 * 	- The end of the path of the current directory.
 *	- The position of the last component on it.
 *	- The read position in the directory.
 *	- The file handle of the directory.
 *	- The stat of the directory.
 */
typedef struct traverse_state {
	char *ts_end;
	char *ts_ent;
	long ts_dpos; /* position in the directory when reading its entries */
	fs_fhandle_t ts_fh;
	struct stat64 ts_st;
} traverse_state_t;

typedef struct {
	struct stat64 fd_attr;
	fs_fhandle_t fd_fh;
	short fd_len;
	char fd_name[1];
} fs_dent_info_t;

typedef struct dent_arg {
	char *da_buf;
	int da_end;
	int da_size;
} dent_arg_t;

static int traverse_level_nondir(struct fs_traverse *ftp,
    traverse_state_t *tsp, struct fst_node *pnp);

/*
 * Creates a new traversing state based on the path passed to it.
 */
static traverse_state_t *
new_tsp(char *path)
{
	traverse_state_t *tsp;
	tsp = ndmp_malloc(sizeof (traverse_state_t));
	if (!tsp)
		return (NULL);

	tsp->ts_end = strchr(path, '\0');
	if (*(tsp->ts_end-1) == '/')
		*--tsp->ts_end = '\0';
	tsp->ts_ent = NULL;
	tsp->ts_dpos = 0;

	return (tsp);
}

/*
 * Create a file handle and get stats for the given path
 */
int
fs_getstat(char *path, fs_fhandle_t *fh, struct stat64 *st)
{
	if (lstat64(path, st) == -1) {
		syslog(LOG_INFO,
		    "lstat64() says [%s] not found errno=(%d)", path, errno);
		return (errno);
	}

	fh->fh_fid = st->st_ino;

	if (!S_ISDIR(st->st_mode))
		fh->fh_fpath = NULL;
	else
		fh->fh_fpath = strdup(path);
	return (0);
}

/*
 * Read the directory entries and return the information about
 * each entry
 */
int
fs_readdir(fs_fhandle_t *ts_fh, char *path, long *dpos,
    char *nm, int *el, fs_fhandle_t *efh, struct stat64 *est)
{
	struct dirent *dp;
	char  file_path[PATH_MAX + 1];
	DIR *dirp;
	int rv;

	if ((dirp = opendir(ts_fh->fh_fpath)) == NULL)
		return (errno);

	seekdir(dirp, *dpos);
	if ((dp = readdir(dirp)) == NULL) {
		rv = 0;  /* skip this dir */
		*el = 0;
	} else {
		(void) snprintf(file_path, PATH_MAX, "%s/", path);
		(void) strlcat(file_path, dp->d_name, PATH_MAX + 1);

		rv = fs_getstat(file_path, efh, est);
		if (rv == 0) {
			*dpos = telldir(dirp);
			(void) strlcpy(nm, dp->d_name, NAME_MAX + 1);
			*el = strlen(dp->d_name);
		} else {
			*el = 0;
		}
	}
	(void) closedir(dirp);
	return (rv);
}

/*
 * Traverse the file system in the post-order way.  The description
 * and example is in the header file.
 *
 * The callback function should return 0, on success and non-zero on
 * failure.  If the callback function returns non-zero return value,
 * the traversing stops.
 */
int
traverse_post(struct fs_traverse *ftp)
{
	char path[PATH_MAX + 1]; /* full path name of the current dir */
	char nm[NAME_MAX + 1]; /* directory entry name */
	char *lp; /* last position on the path */
	int next_dir, rv;
	int pl, el; /* path and directory entry length */
	cstack_t *sp;
	fs_fhandle_t pfh, efh;
	struct stat64 pst, est;
	traverse_state_t *tsp;
	struct fst_node pn, en; /* parent and entry nodes */

	if (!ftp || !ftp->ft_path || !*ftp->ft_path || !ftp->ft_callbk) {
		errno = EINVAL;
		return (-1);
	}

	/* set the default log function if it's not already set */
	if (!ftp->ft_logfp) {
		ftp->ft_logfp = (ft_log_t)syslog;
		syslog(LOG_DEBUG, "Log to system log \"%s\"", ftp->ft_path);
	}

	/* set the logical path to physical path if it's not already set */
	if (!ftp->ft_lpath) {
		syslog(LOG_DEBUG,
		    "report the same paths: \"%s\"", ftp->ft_path);
		ftp->ft_lpath = ftp->ft_path;
	}

	pl = strlen(ftp->ft_lpath);
	if (pl + 1 > PATH_MAX) { /* +1 for the '/' */
		syslog(LOG_ERR, "lpath too long \"%s\"", ftp->ft_path);
		errno = ENAMETOOLONG;
		return (-1);
	}
	(void) strcpy(path, ftp->ft_lpath);
	(void) memset(&pfh, 0, sizeof (pfh));
	rv = fs_getstat(ftp->ft_lpath, &pfh, &pst);

	if (rv != 0) {
		syslog(LOG_ERR,
		    "Error %d on fs_getstat(%s)", rv, ftp->ft_path);
		return (rv);
	}

	if (!S_ISDIR(pst.st_mode)) {
		pn.tn_path = ftp->ft_lpath;
		pn.tn_fh = &pfh;
		pn.tn_st = &pst;
		en.tn_path = NULL;
		en.tn_fh = NULL;
		en.tn_st = NULL;
		rv = CALLBACK(&pn, &en);
		free(pfh.fh_fpath);
		return (rv);
	}

	sp = cstack_new();
	if (!sp) {
		errno = ENOMEM;
		free(pfh.fh_fpath);
		return (-1);
	}
	tsp = new_tsp(path);
	if (!tsp) {
		cstack_delete(sp);
		errno = ENOMEM;
		free(pfh.fh_fpath);
		return (-1);
	}
	tsp->ts_ent = tsp->ts_end;
	tsp->ts_fh = pfh;
	tsp->ts_st = pst;
	pn.tn_path = path;
	pn.tn_fh = &tsp->ts_fh;
	pn.tn_st = &tsp->ts_st;

	rv = 0;
	next_dir = 1;
	do {
		if (next_dir) {
			*tsp->ts_end = '\0';
		}

		next_dir = 0;
		do {
			el = NAME_MAX;
			rv = fs_readdir(&tsp->ts_fh, pn.tn_path,
			    &tsp->ts_dpos, nm, &el,
			    &efh, &est);

			if (rv != 0) {
				syslog(LOG_ERR,
				    "Error %d on readdir(%s) pos %d",
				    rv, path, tsp->ts_dpos);
				if (STOP_ONERR(ftp))
					break;
				rv = SKIP_ENTRY;

				continue;
			}

			/* done with this directory */
			if (el == 0) {
				break;
			}
			nm[el] = '\0';

			if (rootfs_dot_or_dotdot(nm)) {
				free(efh.fh_fpath);
				continue;
			}

			if (pl + 1 + el > PATH_MAX) {
				syslog(LOG_ERR, "Path %s/%s is too long.",
				    path, nm);
				if (STOP_ONLONG(ftp))
					rv = ENAMETOOLONG;
				free(efh.fh_fpath);
				continue;
			}

			/*
			 * Push the current directory on to the stack and
			 * dive into the entry found.
			 */
			if (S_ISDIR(est.st_mode)) {

				assert(tsp != NULL);
				if (cstack_push(sp, tsp, 0)) {
					rv = ENOMEM;
					free(efh.fh_fpath);
					break;
				}

				/*
				 * Concatenate the current entry with the
				 * current path.  This will be the path of
				 * the new directory to be scanned.
				 *
				 * Note:
				 * sprintf(tsp->ts_end, "/%s", de->d_name);
				 * could be used here, but concatenating
				 * strings like this might be faster.
				 * The length of the new path has been
				 * checked above.  So strcpy() can be
				 * safe and should not lead to a buffer
				 * over-run.
				 */
				lp = tsp->ts_end;
				*tsp->ts_end = '/';
				(void) strcpy(tsp->ts_end + 1, nm);

				tsp = new_tsp(path);
				if (!tsp) {
					free(efh.fh_fpath);
					rv = ENOMEM;
				} else {
					next_dir = 1;
					pl += el;
					tsp->ts_fh = efh;
					tsp->ts_st = est;
					tsp->ts_ent = lp;
					pn.tn_fh = &tsp->ts_fh;
					pn.tn_st = &tsp->ts_st;
				}
				break;
			} else {
				/*
				 * The entry is not a directory so the
				 * callback function must be called.
				 */
				en.tn_path = nm;
				en.tn_fh = &efh;
				en.tn_st = &est;
				rv = CALLBACK(&pn, &en);
				free(efh.fh_fpath);
				if (rv != 0)
					break;
			}
		} while (rv == 0);

		/*
		 * A new directory must be processed, go to the start of
		 * the loop, open it and process it.
		 */
		if (next_dir)
			continue;

		if (rv == SKIP_ENTRY)
			rv = 0; /* We should skip the current directory */

		if (rv == 0) {
			/*
			 * Remove the ent from the end of path and send it
			 * as an entry of the path.
			 */
			lp = tsp->ts_ent;
			*lp = '\0';
			efh = tsp->ts_fh;
			est = tsp->ts_st;
			free(tsp);
			if (cstack_pop(sp, (void **)&tsp, (int *)NULL))
				break;

			assert(tsp != NULL);
			pl = tsp->ts_end - path;

			pn.tn_fh = &tsp->ts_fh;
			pn.tn_st = &tsp->ts_st;
			en.tn_path = lp + 1;
			en.tn_fh = &efh;
			en.tn_st = &est;

			rv = CALLBACK(&pn, &en);
			free(efh.fh_fpath);
			/*
			 * Does not need to free tsp here.  It will be released
			 * later.
			 */
		}

		if (rv != 0 && tsp) {
			free(tsp->ts_fh.fh_fpath);
			free(tsp);
		}

	} while (rv == 0);

	/*
	 * For the 'ftp->ft_path' directory itself.
	 */
	if (rv == 0) {
		pn.tn_fh = &efh;
		pn.tn_st = &est;
		en.tn_path = NULL;
		en.tn_fh = NULL;
		en.tn_st = NULL;
		rv = CALLBACK(&pn, &en);
	}

	/*
	 * Pop and free all the remaining entries on the stack.
	 */
	while (!cstack_pop(sp, (void **)&tsp, (int *)NULL)) {
		free(tsp->ts_fh.fh_fpath);
		free(tsp);
	}

	cstack_delete(sp);
	return (rv);
}

/*
 * In one pass, read all the directory entries of the specified
 * directory and call the callback function for non-directory
 * entries.
 *
 * On return:
 *    0: Lets the directory to be scanned for directory entries.
 *    < 0: Completely stops traversing.
 *    FST_SKIP: stops further scanning of the directory.  Traversing
 *        will continue with the next directory in the hierarchy.
 *    SKIP_ENTRY: Failed to get the directory entries, so the caller
 *	  should skip this entry.
 */
static int
traverse_level_nondir(struct fs_traverse *ftp,
    traverse_state_t *tsp, struct fst_node *pnp)
{
	struct stat64 st;
	fs_fhandle_t fh;
	DIR *dp;
	struct dirent *dirp;
	struct fst_node en; /* entry node */
	char path[MAXPATHLEN+MAXNAMELEN+2];
	int rv = 0;

	if ((dp = opendir(tsp->ts_fh.fh_fpath)) == NULL) {
		syslog(LOG_ERR,
		    "traverse_level_nondir: open directory "
		    "%s failed: %m", tsp->ts_fh.fh_fpath);
		return (errno);
	}

	while ((dirp = readdir(dp)) != NULL) {
		if ((strcmp(dirp->d_name, ".") == 0) ||
		    (strcmp(dirp->d_name, "..") == 0)) {
			continue;
		}

		if (!tlm_cat_path(path, tsp->ts_fh.fh_fpath,
		    dirp->d_name)) {
			continue;
		}

		if (lstat64(path, &st) != 0) {
			syslog(LOG_ERR,
			    "traverse_level_nondir: failed to get file"
			    " status for %s skipping: %m", tsp->ts_fh.fh_fpath);
			continue;
		}
		fh.fh_fid = st.st_ino;

		/*
		 * The entry is not a directory so the callback
		 * function must be called.
		 */
		if (!S_ISDIR(st.st_mode)) {
			en.tn_path = dirp->d_name;
			en.tn_fh = &fh;
			en.tn_st = &st;
			rv = CALLBACK(pnp, &en);
			if (rv < 0) {
				syslog(LOG_DEBUG,
				    "traverse_level_nondir: result is %d "
				    "with %s", rv, path);
				break;
			}
			if (rv == FST_SKIP) {
				syslog(LOG_DEBUG,
				    "traverse_level_nondir: skipping "
				    "%s", path);
				break;
			}
		}
	}

	(void) closedir(dp);
	return (rv);
}

/*
 * Traverse the file system in the level-order way.  The description
 * and example is in the header file.
 */
int
traverse_level(struct fs_traverse *ftp)
{
	char path[PATH_MAX + 1];	/* full path name of the current dir */
	char nm[NAME_MAX + 1];	/* directory entry name */
	char *lp;		/* last position on the path */
	int next_dir, rv;
	int pl, el;		/* path and directory entry length */

	cstack_t *sp;
	fs_fhandle_t pfh, efh;
	struct stat64 pst, est;
	traverse_state_t *tsp;
	struct fst_node pn, en;  /* parent and entry nodes */

	if (!ftp || !ftp->ft_path || !*ftp->ft_path || !ftp->ft_callbk) {
		errno = EINVAL;
		return (-1);
	}
	/* set the default log function if it's not already set */
	if (!ftp->ft_logfp) {
		ftp->ft_logfp = (ft_log_t)syslog;
		syslog(LOG_DEBUG, "Log to system log \"%s\"", ftp->ft_path);
	}
	if (!ftp->ft_lpath) {
		syslog(LOG_DEBUG,
		    "report the same paths \"%s\"", ftp->ft_path);
		ftp->ft_lpath = ftp->ft_path;
	}

	pl = strlen(ftp->ft_lpath);
	if (pl + 1 > PATH_MAX) { /* +1 for the '/' */
		syslog(LOG_ERR, "lpath too long \"%s\"", ftp->ft_path);
		errno = ENAMETOOLONG;
		return (-1);
	}
	(void) strcpy(path, ftp->ft_lpath);
	(void) memset(&pfh, 0, sizeof (pfh));
	rv = fs_getstat(ftp->ft_lpath, &pfh, &pst);
	if (rv != 0) {
		syslog(LOG_DEBUG,
		    "Error %d on fs_getstat(%s)", rv, ftp->ft_lpath);
		return (-1);
	}

	en.tn_path = NULL;
	en.tn_fh = NULL;
	en.tn_st = NULL;
	if (!S_ISDIR(pst.st_mode)) {
		pn.tn_path = ftp->ft_lpath;
		pn.tn_fh = &pfh;
		pn.tn_st = &pst;
		rv = CALLBACK(&pn, &en);
		free(pfh.fh_fpath);
		return (rv);
	}

	sp = cstack_new();
	if (!sp) {
		free(pfh.fh_fpath);
		errno = ENOMEM;
		return (-1);
	}
	tsp = new_tsp(path);
	if (!tsp) {
		cstack_delete(sp);
		free(pfh.fh_fpath);
		errno = ENOMEM;
		return (-1);
	}

	tsp->ts_ent = tsp->ts_end;
	tsp->ts_fh = pfh;
	tsp->ts_st = pst;
	pn.tn_path = path;
	pn.tn_fh = &tsp->ts_fh;
	pn.tn_st = &tsp->ts_st;

	/* call the callback function on the path itself */
	rv = CALLBACK(&pn, &en);
	if (rv < 0) {
		free(tsp);
		goto end;
	}
	if (rv == FST_SKIP) {
		free(tsp);
		rv = 0;
		goto end;
	}

	rv = 0;
	next_dir = 1;
	do {
		if (next_dir) {
			*tsp->ts_end = '\0';
			rv = traverse_level_nondir(ftp, tsp, &pn);
			if (rv < 0) {
				NEGATE(rv);
				free(tsp->ts_fh.fh_fpath);
				free(tsp);
				break;
			}
			/*
			 * If skipped by the callback function or
			 * error happened reading the information
			 */
			if (rv == FST_SKIP || rv == SKIP_ENTRY) {
				/*
				 * N.B. next_dir should be set to 0 as
				 * well. This prevents the infinite loop.
				 * If it's not set the same directory will
				 * be poped from the stack and will be
				 * scanned again.
				 */
				next_dir = 0;
				rv = 0;
				goto skip_dir;
			}

			/* re-start reading entries of the directory */
			tsp->ts_dpos = 0;
		}

		next_dir = 0;
		do {
			el = NAME_MAX;
			rv = fs_readdir(&tsp->ts_fh, pn.tn_path,
			    &tsp->ts_dpos, nm, &el, &efh,
			    &est);
			if (rv != 0) {
				syslog(LOG_DEBUG,
				    "Error %d on readdir(%s) pos %d",
				    rv, path, tsp->ts_dpos);
				if (STOP_ONERR(ftp))
					break;
				rv = SKIP_ENTRY;
				continue;
			}

			/* done with this directory */
			if (el == 0)
				break;

			nm[el] = '\0';

			if (rootfs_dot_or_dotdot(nm)) {
				free(efh.fh_fpath);
				continue;
			}

			if (pl + 1 + el > PATH_MAX) {
				/*
				 * The long paths were already encountered
				 * when processing non-dir entries in.
				 * traverse_level_nondir.
				 * We don't increase fss_longpath_err
				 * counter for them again here.
				 */
				syslog(LOG_ERR, "Path %s/%s is too long.",
				    path, nm);
				if (STOP_ONLONG(ftp))
					rv = ENAMETOOLONG;
				free(efh.fh_fpath);
				continue;
			}

			if (!S_ISDIR(est.st_mode))
				continue;

			/*
			 * Call the callback function for the new
			 * directory found, then push the current
			 * directory on to the stack.  Then dive
			 * into the entry found.
			 */
			en.tn_path = nm;
			en.tn_fh = &efh;
			en.tn_st = &est;
			rv = CALLBACK(&pn, &en);

			if (rv < 0) {
				NEGATE(rv);
				free(efh.fh_fpath);
				break;
			}
			if (rv == FST_SKIP) {
				free(efh.fh_fpath);
				rv = 0;
				continue;
			}

			/*
			 * Push the current directory on to the stack and
			 * dive into the entry found.
			 */
			if (cstack_push(sp, tsp, 0)) {
				rv = ENOMEM;
			} else {
				lp = tsp->ts_end;
				*tsp->ts_end = '/';
				(void) strcpy(tsp->ts_end + 1, nm);

				tsp = new_tsp(path);
				if (!tsp)
					rv = ENOMEM;
				else {
					next_dir = 1;
					pl += el + 1;
					tsp->ts_fh = efh;
					tsp->ts_st = est;
					tsp->ts_ent = lp;
					pn.tn_fh = &tsp->ts_fh;
					pn.tn_st = &tsp->ts_st;
				}
			}
			break;

		} while (rv == 0);

		/*
		 * A new directory must be processed, go to the start of
		 * the loop, open it and process it.
		 */
		if (next_dir)
			continue;
skip_dir:
		if (tsp) {
			free(tsp->ts_fh.fh_fpath);
			free(tsp);
		}

		if (rv == SKIP_ENTRY)
			rv = 0;

		if (rv == 0) {
			if (cstack_pop(sp, (void **)&tsp, (int *)NULL))
				break;

			*tsp->ts_end = '\0';
			pl = tsp->ts_end - path;
			pn.tn_fh = &tsp->ts_fh;
			pn.tn_st = &tsp->ts_st;
		}
	} while (rv == 0);

	/*
	 * Pop and free all the remaining entries on the stack.
	 */
	while (!cstack_pop(sp, (void **)&tsp, (int *)NULL)) {
		free(tsp->ts_fh.fh_fpath);
		free(tsp);
	}
end:
	cstack_delete(sp);
	return (rv);
}

/*
 * filecopy - Copy a file
 *
 * Parameters:
 *  char *dest  - Destination path
 *  char *src   - Source path
 *
 * Returns:
 *  0    - No errors
 *  #0   - Error occured
 *		-4   - read/write error
 *		-5   - source modified during copy
 *
 * Simplified version for Solaris
 */
#define	BUFSIZE	32768
int
filecopy(char *dest, char *src)
{
	FILE *src_fh = 0;
	FILE *dst_fh = 0;
	struct stat64 src_attr;
	struct stat64 dst_attr;
	char *buf = 0;
	u_longlong_t bytes_to_copy;
	size_t nbytes;
	int file_copied = 0;

	buf = ndmp_malloc(BUFSIZE);
	if (!buf)
		return (-1);

	src_fh = fopen(src, "r");
	if (src_fh == 0) {
		free(buf);
		return (-2);
	}

	dst_fh = fopen(dest, "w");
	if (dst_fh == NULL) {
		free(buf);
		(void) fclose(src_fh);
		return (-3);
	}

	if (stat64(src, &src_attr) < 0) {
		free(buf);
		(void) fclose(src_fh);
		(void) fclose(dst_fh);
		return (-2);
	}

	bytes_to_copy = src_attr.st_size;
	while (bytes_to_copy) {
		if (bytes_to_copy > BUFSIZE)
			nbytes = BUFSIZE;
		else
			nbytes = bytes_to_copy;

		if ((fread(buf, nbytes, 1, src_fh) != 1) ||
		    (fwrite(buf, nbytes, 1, dst_fh) != 1))
			break;
		bytes_to_copy -= nbytes;
	}

	(void) fclose(src_fh);
	(void) fclose(dst_fh);

	if (bytes_to_copy > 0) {
		free(buf);
		/* short read/write, remove the partial file */
		return (-4);
	}

	if (stat64(src, &dst_attr) < 0) {
		free(buf);
		return (-2);
	}

	free(buf);

	if (!file_copied)
		return (-5);	/* source modified during copy */
	else
		return (0);
}

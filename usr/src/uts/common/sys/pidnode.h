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
 * Copyright 2015 Mohamed A. Khalfella <khalfella@gmail.com>
 */

#ifndef _SYS_PIDNODE_H
#define	_SYS_PIDNODE_H

#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Network connections initiated/accepted by user processes are either
 * socket-based connections or stream-based connections. conn_pid_info_t
 * exposes the type of the connection in the cpi_contents field.
 */

#define	CONN_PID_INFO_NON	0	/* terminated process/kernel sockets */
#define	CONN_PID_INFO_SOC	1	/* socket network connection */
#define	CONN_PID_INFO_XTI	2	/* stream network connection */

typedef struct conn_pid_info_s {
	uint16_t	cpi_contents;	/* CONN_PID_INFO_* */
	uint32_t	cpi_pids_cnt;	/* # of elements in cpi_pids */
	uint32_t	cpi_tot_size;	/* total size of hdr + pids */
	pid_t		cpi_pids[1];	/* variable length array of pids */
} conn_pid_info_t;

#if defined(_KERNEL)

typedef struct pid_node_s {
	avl_node_t	pn_ref_link;
	uint32_t	pn_count;
	pid_t		pn_pid;
} pid_node_t;

extern int pid_node_comparator(const void *, const void *);

#endif /* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PIDNODE_H */

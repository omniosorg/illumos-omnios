#!/usr/sbin/dtrace -s

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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Quanitize the time spent in each NFSv3 andf NFSv4 operation,
 * optionally for a specified client and share.
 *
 * usage:   nfs_time.d
 * usage:   nfs_time.d <client ip>   <share path>
 * example: nfs_time.d 192.168.123.1 /mypool/fs1
 *
 * It is valid to specify <client ip> or <share path> as "all" to
 * quantize data for all clients and/or all shares.
 * example: nfs_time.d 192.168.123.1 all
 * example: nfs_time.d all /mypool/fs1
 * example: nfs_time.d all all
 */

#pragma D option flowindent
#pragma D option defaultargs

dtrace:::BEGIN
{
	client = ($$1 == NULL) ? "all" : $$1;
	share = ($$2 == NULL) ? "all" : $$2;
	printf("%Y - client=%s share=%s\n", walltimestamp, client, share);
}

nfsv3:::op-*-start,
nfsv4:::op-*-start
/ ((client == "all") || (args[0]->ci_remote == client)) &&
   ((share == "all") || (args[1]->noi_shrpath == share)) /
{
	self->ts[probefunc] = timestamp;
}

nfsv3:::op-*-done,
nfsv4:::op-*-done
/ ((client == "all") || (args[0]->ci_remote == client)) &&
   ((share == "all") || (args[1]->noi_shrpath == share)) /
{
	elapsed = (timestamp - self->ts[probefunc]);
	@q[probefunc]=quantize(elapsed);
}

tick-5s
{
	printa(@q);
	/*
	 * uncomment "clear" to quantize per 5s interval
	 * rather than cumulative for duration of script.
	 * clear(@q);
	 */
}

dtrace:::END
{
}

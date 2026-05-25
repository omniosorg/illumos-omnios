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
 * Copyright 2026 Richard Lowe
 */

/*
 * Wait for the service management facility to reach a steady state
 */

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include <libscf.h>

extern const char *__progname;

/* Just count up any instances we see */
int
count_instances_cb(scf_handle_t *hdl, scf_instance_t *inst, void *arg)
{
	*(int *)arg += 1;

	return (SCF_SUCCESS);
}

/* Report services which didn't make it */
int
report_losers_cb(scf_handle_t *hdl, scf_instance_t *inst, void *arg)
{
	char instance_name[BUFSIZ];
	char service_name[BUFSIZ];
	scf_service_t *svc = NULL;

	if (scf_instance_get_name(inst, instance_name, BUFSIZ) == SCF_FAILED) {
		errx(1, "couldn't get instance name: %s\n",
		    scf_strerror(scf_error()));
	}

	if ((svc = scf_service_create(hdl)) == NULL) {
		errx(1, "couldn't allocate service: %s",
		    scf_strerror(scf_error()));
	}

	if (scf_instance_get_parent(inst, svc) == SCF_FAILED) {
		errx(1, "couldn't get service of instance: %s\n",
		    scf_strerror(scf_error()));
	}

	if (scf_service_get_name(svc, service_name, BUFSIZ) == SCF_FAILED) {
		errx(1, "couldn't get name of service of instance: %s\n",
		    scf_strerror(scf_error()));
	}

	printf("svc:/%s:%s didn't make it\n", service_name, instance_name);

	scf_service_destroy(svc);

	return (SCF_SUCCESS);
}

/*
 * The set of states which indicate the service is still on its way
 * somewhere.
 */
const int CHUGGING_STATES = SCF_STATE_UNINIT | \
    SCF_STATE_OFFLINE;

/*
 * The set of states that indicate problems.  A superset of `CHUGGING_STATES`
 * since anyone in one of those when we think we're done is also problematic
 */
const int FAILED_STATES = CHUGGING_STATES | SCF_STATE_MAINT | \
    SCF_STATE_DEGRADED;

/*
 * How many ticks we want to remain at 0 chugging services before we're done
 */
const int WAIT_TICKS = 3;

/* How long to sleep between checks */
const int SLEEP_FOR = 1;

int
main(int argc, char **argv)
{
	uint_t svccount;	/* Number of chugging services right now */
	uint_t tickcount = WAIT_TICKS;

	if (argc != 1)
		errx(1, "usage: %s\n", __progname);

	do {
		svccount = 0;

		if (scf_simple_walk_instances(CHUGGING_STATES,
		    &svccount, count_instances_cb) == SCF_FAILED) {
			errx(1, "couldn't walk instances: %s\n",
			    scf_strerror(scf_error()));
		}

		if (svccount != 0) {
			printf("\r%3d instances to wait for", svccount);
			fflush(stdout);
			tickcount = WAIT_TICKS;
		} else {
			tickcount--;
		}

		(void) sleep(SLEEP_FOR);
	} while ((svccount > 0) && (tickcount > 0));

	/*
	 * There are better ways to do this, but this works even when $TERM is
	 * incorrect, like on the console of a platform image.
	 */
	printf("\r                                      \r");
	fflush(stdout);

	/* Now report any services which aren't in a good state */
	if (scf_simple_walk_instances(FAILED_STATES,
	    NULL, report_losers_cb) == SCF_FAILED) {
		errx(1, "couldn't walk instances: %s\n",
		    scf_strerror(scf_error()));
	}

	return (EXIT_SUCCESS);
}

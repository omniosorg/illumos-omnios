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
 * Copyright 2025 Michael van der Westhuizen
 */

#ifndef _LIBFDTUART_FDTUART_H
#define	_LIBFDTUART_FDTUART_H

#define	FDTUART_BAD_CLOCK_CELLS		0xFFFFFFFF

/*
 * MMIO UART types and declarations.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int fdtuart_phandle_from_prop(const void *fdtp,
    int nodeoff, const char *propname);
extern bool fdtuart_node_status_okay(const void *fdtp, int nodeoff);
extern uint32_t fdtuart_get_clock_cells(const void *fdtp, int nodeoff);

extern bool fdtuart_resolve_reg(const void *fdtp, int nodeoff, int frame,
    uint64_t *reg, uint64_t *reg_len);
extern bool fdtuart_bus_to_phys(const void *fdtp, int nodeoff,
    uint64_t *addr, uint64_t addr_len);
extern bool fdtuart_phys_to_bus(const void *fdtp, int nodeoff,
    uint64_t *addr, uint64_t addr_len);

extern uint64_t fdtuart_get_clock_frequency(const void *fdtp, int nodeoff);
extern uint64_t fdtuart_get_clock_rate(const void *fdtp,
    int nodeoff, int which);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFDTUART_FDTUART_H */

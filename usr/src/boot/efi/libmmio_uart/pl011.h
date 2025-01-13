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

#ifndef _MMIO_UART_PL011_H
#define	_MMIO_UART_PL011_H

#include <mmio_uart.h>

/*
 * MMIO UART declarations for Arm PL011 compatible UARTs.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t		pl_addr;
	uint64_t		pl_addr_len;
	uint64_t		pl_frequency;
	mmio_uart_type_t	pl_variant;

	/* cached register values */
	uint16_t		pl_ibrd;
	uint8_t			pl_fbrd;
	uint8_t			pl_lcr;
	uint16_t		pl_cr;
} pl011_info_t;

extern const mmio_uart_ops_t mmio_uart_pl011_ops;

#ifdef __cplusplus
}
#endif

#endif /* _MMIO_UART_PL011_H */

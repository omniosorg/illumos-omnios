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

#ifndef _MMIO_UART_MMIO_UART_H
#define	_MMIO_UART_MMIO_UART_H

/*
 * MMIO UART types and declarations.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flags for the mu_flags field.
 *
 * MMIO_UART_VALID
 *   This UART configuration is valid (fully specified).
 *
 * MMIO_UART_STDOUT
 *   This UART is the firmware-selected stdout device (via
 *   /chosen/stdout-path in FDT or SPCR is ACPI). This flag is used to avoid
 *   interacting with this UART, deferring to the UEFI console for interations.
 *
 * MMIO_UART_CONFIG_FW_SPECIFIED
 *   The configuration for this UART was specified by firmware and should not
 *   be changed. This is the case for SPCR and for parameters specified via
 *   /chosen/stdout-path. On FDT systems you should update the
 *   /chosen/stdout-path variable to configure the UART and on ACPI systems
 *   you should update the communication settings in the UEFI settings.
 *   When this is set, then MMIO_UART_CONFIG_LOCKED is also set.
 *
 * MMIO_UART_CONFIG_FROM_HW
 *   The UART configuration is managed by firmware but not communicated via
 *   firmware tables. The configuration should be derived from the hardware
 *   and otherwise left alone. When this is set, then MMIO_UART_CONFIG_LOCKED
 *   is also set.
 *
 * MMIO_UART_CONFIG_LOCKED
 *   The UART configuration parameters should not be reprogrammed.
 *
 * MMIO_UART_PROBED
 *   UART has been probed.
 *
 * Also note that if the implementation cannot determine the clock frequency
 * driving the UART it will reject any attempts to change the UART speed. In
 * this case a default speed will be reported. See MMIO_UART_DEFAULT_COMSPEED
 * the the default that will be used.
 */
#define	MMIO_UART_VALID			0x1
#define	MMIO_UART_STDOUT		0x2
#define	MMIO_UART_CONFIG_FW_SPECIFIED	0x4
#define	MMIO_UART_CONFIG_LOCKED		0x8
#define	MMIO_UART_CONFIG_FROM_HW	0x10
#define	MMIO_UART_PROBED		0x20

/*
 * These values are from the ACPI DBG2 specification, stewarded by Microsoft.
 *
 * The values correspond to the debug port subtype, and are reused in the
 * Serial Port Console Redirect (SPCR) specification, also stewarded by
 * Microsoft.
 */
typedef enum {
	MMIO_UART_TYPE_NS16550_OLD = 0x01,
	MMIO_UART_TYPE_PL011 = 0x03,
	MMIO_UART_TYPE_ARM_GENERIC = 0x0e,	/* limited functionality */
	MMIO_UART_TYPE_NS16550 = 0x12
} mmio_uart_type_t;

typedef enum {
	MMIO_UART_DATA_BITS_8 = 8,
	MMIO_UART_DATA_BITS_7 = 7,
	MMIO_UART_DATA_BITS_6 = 6,
	MMIO_UART_DATA_BITS_5 = 5
} mmio_uart_data_bits_t;

typedef enum {
	MMIO_UART_PARITY_EVEN = 1,
	MMIO_UART_PARITY_ODD = 2,
	MMIO_UART_PARITY_NONE = 3,
	MMIO_UART_PARITY_MARK = 4,
	MMIO_UART_PARITY_SPACE = 5
} mmio_uart_parity_t;

typedef enum {
	MMIO_UART_STOP_BITS_1 = 1,
	MMIO_UART_STOP_BITS_2 = 2,
	MMIO_UART_STOP_BITS_1_5 = 3
} mmio_uart_stop_bits_t;

#define	MMIO_UART_DEFAULT_COMSPEED	115200

typedef uint64_t mmio_uart_speed_t;

typedef struct {
	bool	(*op_setup)(void *);
	bool	(*op_config_check)(void *, mmio_uart_speed_t,
	    mmio_uart_data_bits_t, mmio_uart_parity_t, mmio_uart_stop_bits_t);
	bool	(*op_has_carrier)(void *);
	void	(*op_putchar)(void *, int);
	int	(*op_getchar)(void *);
	int	(*op_getspeed)(void *);
	int	(*op_ischar)(void *);
	void	(*op_devinfo)(void *);
	int	(*op_make_tty_hook)(void *);
	void	(*op_set_environment)(void *);
} mmio_uart_ops_t;

typedef void * mmio_uart_ctx_t;

typedef struct {
	uint64_t mu_base;
	mmio_uart_type_t mu_type;
	mmio_uart_speed_t mu_speed;
	mmio_uart_data_bits_t mu_data_bits;
	mmio_uart_parity_t mu_parity;
	mmio_uart_stop_bits_t mu_stop_bits;
	bool mu_ignore_cd;
	bool mu_rtsdtr_off;
	const mmio_uart_ops_t	*mu_ops;
	mmio_uart_ctx_t	mu_ctx;
	char *mu_fwpath;
	uint32_t mu_serial_idx;
	char *mu_fwname;
	uint32_t mu_flags;
} mmio_uart_t;


struct console;
extern struct console *mmio_uart_make_tty(mmio_uart_t *uart);

extern void *mmio_uart_alloc_low_page(void);
extern void mmio_uart_free_low_page(void *addr);

extern void mmio_uart_puts(const char *s);
extern void mmio_uart_putn(unsigned long n, int b);

#ifdef __cplusplus
}
#endif

#endif /* _MMIO_UART_MMIO_UART_H */

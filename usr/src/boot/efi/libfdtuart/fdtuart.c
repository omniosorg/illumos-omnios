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

/*
 * Scan the FDT and create MMIO UART-backed consoles for each supported UART.
 */

#include <mmio_uart.h>
#include <pl011.h>
#include <bootstrap.h>
#include <libfdt.h>

#include "fdtuart.h"

/*
 * An arbitrary restriction on the number of UARTs we're prepared to discover.
 *
 * This gives us ttya->ttyz.
 */
#define	MAX_UARTS	26

typedef struct {
	const char		*fum_compatible;
	mmio_uart_type_t	fum_type;
} fdt_uart_match_t;

static const fdt_uart_match_t fdt_uart_match[] = {
	{ "arm,pl011", MMIO_UART_TYPE_PL011 },
};
static size_t num_fdt_uart_match =
    sizeof (fdt_uart_match) / sizeof (fdt_uart_match[0]);

static mmio_uart_t mmio_uart[MAX_UARTS];
static size_t num_mmio_uart;

static pl011_info_t pl011_info[MAX_UARTS];
static size_t num_pl011_info;

/*
 * Return 1 if the node is compatible, 0 otherwise.
 *
 * If a pointer is passed in uart_type it is filled with the MMIO UART type.
 */
static bool
fdtuart_node_is_compatible_uart(const void *fdtp, int nodeoff,
    mmio_uart_type_t *uart_type)
{
	size_t n;

	for (n = 0; n < num_fdt_uart_match; ++n) {
		if (fdt_node_check_compatible(fdtp, nodeoff,
		    fdt_uart_match[n].fum_compatible) == 0) {
			if (uart_type)
				*uart_type = fdt_uart_match[n].fum_type;
			return (true);
		}
	}

	return (false);
}

/*
 * For UART devices, the preferred binding is a string in the form:
 *   <baud>{<parity>{<bits>{<flow>}}}
 * where
 *   baud       - baud rate in decimal
 *   parity     - 'n' (none), 'o', (odd) or 'e' (even)
 *   bits       - number of data bits
 *   flow       - 'r' (rts)
 *
 * For example: 115200n8r
 */
static void
fdtuart_parse_generic_stdout_path_params(const char *param, mmio_uart_t *uart)
{
	long speed_;
	char *ep;

	mmio_uart_speed_t speed;
	mmio_uart_data_bits_t data_bits;
	mmio_uart_parity_t parity;
	bool rtsdtr_off;

	if (param == NULL || *param == '\0' || uart == NULL)
		return;

	parity = MMIO_UART_PARITY_NONE;
	data_bits = MMIO_UART_DATA_BITS_8;
	rtsdtr_off = false;

	speed_ = strtol(param, &ep, 10);
	if (speed_ <= 0 || speed_ == LONG_MIN || speed_ == LONG_MAX)
		return;
	speed = (mmio_uart_speed_t)speed_;

	if (*ep != '\0') {
		switch (*ep) {
		case 'n':
			parity = MMIO_UART_PARITY_NONE;
			break;
		case 'o':
			parity = MMIO_UART_PARITY_ODD;
			break;
		case 'e':
			parity = MMIO_UART_PARITY_EVEN;
			break;
		default:
			return;
		}

		++ep;
	}

	if (*ep != '\0') {
		switch (*ep) {
		case '8':
			data_bits = MMIO_UART_DATA_BITS_8;
			break;
		case '7':
			data_bits = MMIO_UART_DATA_BITS_7;
			break;
		case '6':
			data_bits = MMIO_UART_DATA_BITS_6;
			break;
		case '5':
			data_bits = MMIO_UART_DATA_BITS_5;
			break;
		default:
			return;
		}

		++ep;
	}

	if (*ep != '\0') {
		if (*ep != 'r')
			return;
		rtsdtr_off = false;
		++ep;
	} else {
		rtsdtr_off = true;
	}

	/* trailing garbage */
	if (*ep != '\0')
		return;

	/*
	 * stop bits will always be 1
	 */

	uart->mu_speed = speed;
	uart->mu_data_bits = data_bits;
	uart->mu_parity = parity;
	uart->mu_stop_bits = MMIO_UART_STOP_BITS_1;
	uart->mu_ignore_cd = true;
	uart->mu_rtsdtr_off = rtsdtr_off;

	uart->mu_flags |= MMIO_UART_CONFIG_FW_SPECIFIED;
}

static bool
fdtuart_process_pl011_node(const void *fdtp, int nodeoff,
    mmio_uart_type_t uart_type)
{
	uint64_t reg;
	uint64_t reg_size;
	uint64_t clock_frequency;

	/*
	 * If there's no more space, bail.
	 */
	if (num_mmio_uart >= MAX_UARTS || num_pl011_info >= MAX_UARTS)
		return (false);

	/*
	 * A PL011 UART has only one register frame.
	 */
	if (!fdtuart_resolve_reg(fdtp, nodeoff, 0, &reg, &reg_size))
		return (false);

	/*
	 * Figure out the UART clock where it's possible to do so.
	 *
	 * If we can't figure this out we leave it as 0, which prevents
	 * the UART implementation from fiddling with the speed.
	 */
	if ((clock_frequency = fdtuart_get_clock_frequency(fdtp, nodeoff)) == 0)
		clock_frequency = fdtuart_get_clock_rate(fdtp, nodeoff, 0);

	pl011_info[num_pl011_info].pl_addr = reg;
	pl011_info[num_pl011_info].pl_addr_len = reg_size;
	pl011_info[num_pl011_info].pl_frequency = clock_frequency;
	pl011_info[num_pl011_info].pl_variant = uart_type;

	mmio_uart[num_mmio_uart].mu_flags = 0;
	mmio_uart[num_mmio_uart].mu_base = reg;
	mmio_uart[num_mmio_uart].mu_type = uart_type;
	mmio_uart[num_mmio_uart].mu_ctx = &pl011_info[num_pl011_info];
	mmio_uart[num_mmio_uart].mu_ops = &mmio_uart_pl011_ops;

	mmio_uart[num_mmio_uart].mu_speed = MMIO_UART_DEFAULT_COMSPEED;
	mmio_uart[num_mmio_uart].mu_data_bits = MMIO_UART_DATA_BITS_8;
	mmio_uart[num_mmio_uart].mu_parity = MMIO_UART_PARITY_NONE;
	mmio_uart[num_mmio_uart].mu_stop_bits = MMIO_UART_STOP_BITS_1;
	mmio_uart[num_mmio_uart].mu_ignore_cd = true;
	mmio_uart[num_mmio_uart].mu_rtsdtr_off = false;

	mmio_uart[num_mmio_uart].mu_flags |= MMIO_UART_VALID;

	++num_pl011_info;
	/* NOTE: num_mmio_uart is bumped by the caller */
	return (true);
}

static bool
fdtuart_process_uart_node(const void *fdtp, int nodeoff,
    mmio_uart_type_t uart_type)
{
	switch (uart_type) {
	case MMIO_UART_TYPE_PL011:
		return (fdtuart_process_pl011_node(fdtp, nodeoff, uart_type));
	default:
		break;
	}

	return (false);
}

static int
fdtuart_get_stdout_path(const void *fdtp, const char **params)
{
	const struct fdt_property *prop;
	const char *propend;
	int chosenoff;
	int proplen;
	int nodeoff;

	if ((chosenoff = fdt_path_offset(fdtp, "/chosen")) < 0)
		return (-1);

	if ((prop = fdt_get_property(fdtp, chosenoff,
	    "stdout-path", &proplen)) == NULL)
		return (-1);	/* no stdout-path property */

	if (proplen == 0)
		return (-1);	/* weird length */

	if ((propend = strstr(prop->data, ":")) == NULL) {
		proplen -= 1;
	} else {
		proplen = propend - prop->data;
	}

	if (*prop->data == '/') {
		nodeoff = fdt_path_offset_namelen(fdtp, prop->data, proplen);
	} else {
		const char *alias_path =
		    fdt_get_alias_namelen(fdtp, prop->data, proplen);
		if (alias_path == NULL)
			return (-1);
		nodeoff = fdt_path_offset(fdtp, alias_path);
	}

	if (nodeoff < 0)
		return (-1);

	if (propend == NULL) {
		*params = NULL;
	} else {
		*params = propend + 1;
	}

	return (nodeoff);
}

static void
fdtuart_find_serial_aliases(const void *fdtp)
{
	const char *propval;
	int offset;
	int stdout;
	const char *params;
	char propname[] = "serial99";
	uint32_t i;
	mmio_uart_type_t	uart_type;

	if ((stdout = fdtuart_get_stdout_path(fdtp, &params)) < 0)
		mmio_uart_puts("WARNING: fdtuart: /chosen/stdout-path "
		    "is not set\n");

	for (i = 0; i < MAX_UARTS; ++i) {
		sprintf(propname, "serial%d", i);

		/* allow gaps */
		if ((propval = fdt_get_alias(fdtp, propname)) == NULL)
			continue;

		/* skip dodgy properties */
		if (*propval == '\0')
			continue;

		if ((offset = fdt_path_offset(fdtp, propval)) < 0) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: "
				    "Broken FDT alias: '");
				mmio_uart_puts(propval);
				mmio_uart_puts("'\n");
			}

			continue;	/* ignore broken aliases */
		}

		/* Skip disabled nodes, but warn if that's the stdout */
		if (!fdtuart_node_status_okay(fdtp, offset)) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: "
				    "/chosen/stdout-path node points to "
				    "a disabled device: '");
				mmio_uart_puts(propval);
				mmio_uart_puts("'\n");
			}

			continue;
		}

		if (!fdtuart_node_is_compatible_uart(
		    fdtp, offset, &uart_type)) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: No driver "
				    "for /chosen/stdout-path path '");
				mmio_uart_puts(propval);
				mmio_uart_puts("'\n");
			}

			continue;
		}

		if ((mmio_uart[num_mmio_uart].mu_fwpath =
		    strdup(propval)) == NULL) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: Failed to "
				    "allocate firmware path for '");
				mmio_uart_puts(propval);
				mmio_uart_puts("'\n");
			}

			continue;
		}

		if ((mmio_uart[num_mmio_uart].mu_fwname =
		    strdup(propname)) == NULL) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: Failed to "
				    "allocate firmware name for '");
				mmio_uart_puts(propname);
				mmio_uart_puts("'\n");
			}

			free(mmio_uart[num_mmio_uart].mu_fwpath);
			mmio_uart[num_mmio_uart].mu_fwpath = NULL;
			continue;
		}

		if (!fdtuart_process_uart_node(fdtp, offset, uart_type)) {
			if (stdout >= 0 && offset == stdout) {
				mmio_uart_puts("WARNING: fdtuart: Failed to "
				    "configure UART for "
				    "/chosen/stdout-path path '");
				mmio_uart_puts(propval);
				mmio_uart_puts("'\n");
			}

			free(mmio_uart[num_mmio_uart].mu_fwname);
			mmio_uart[num_mmio_uart].mu_fwname = NULL;
			free(mmio_uart[num_mmio_uart].mu_fwpath);
			mmio_uart[num_mmio_uart].mu_fwpath = NULL;
			continue;
		}

		mmio_uart[num_mmio_uart].mu_serial_idx = i;

		/*
		 * If the node is the stdout we'll want to keep it
		 * configured as U-Boot configured it.
		 *
		 * If there's no configuration on the stdout-path alias
		 * then we'll pick up the configuration from the
		 * hardware where that's possible.
		 */
		if (stdout >= 0 && offset == stdout) {
			mmio_uart[num_mmio_uart].mu_flags |= MMIO_UART_STDOUT;
			fdtuart_parse_generic_stdout_path_params(
			    params, &mmio_uart[num_mmio_uart]);

			if (!(mmio_uart[num_mmio_uart].mu_flags &
			    MMIO_UART_CONFIG_FW_SPECIFIED)) {
				mmio_uart[num_mmio_uart].mu_flags |=
				    MMIO_UART_CONFIG_FROM_HW;
			}

			mmio_uart[num_mmio_uart].mu_flags |=
			    MMIO_UART_CONFIG_LOCKED;
		}

		num_mmio_uart++;
	}
}

void
fdtuart_discover_uarts(const void *fdtp)
{
	size_t idx;
	size_t c;
	size_t n;
	struct console **tmp;
	struct console *tty;
	struct console *first_tty = NULL;

	if (num_mmio_uart != 0)
		return;

	if (fdt_check_header(fdtp) != 0) {
		mmio_uart_puts("WARNING: fdtuart: bad FDT header\n");
		return;
	}

	fdtuart_find_serial_aliases(fdtp);

	if (num_mmio_uart == 0) {
		mmio_uart_puts("WARNING: fdtuart: no compatible MMIO UARTs\n");
		return;
	}

	n = num_mmio_uart;
	c = cons_array_size();

	if (c == 0)
		n++;

	if ((tmp = realloc(consoles, (c + n) * sizeof (*consoles))) == NULL)
		return;

	consoles = tmp;
	if (c > 0)
		c--;

	for (idx = 0; idx < num_mmio_uart; ++idx) {
		mmio_uart_t *uart = &mmio_uart[idx];

		if ((tty = mmio_uart_make_tty(uart)) == NULL) {
			consoles[c] = tty;
			return;
		}

		if (idx == 0)
			first_tty = tty;

		if ((uart->mu_flags & MMIO_UART_STDOUT) &&
		    getenv("default-uart-name") == NULL) {
			setenv("default-uart-name", tty->c_name, 1);
		}

		consoles[c++] = tty;
	}

	if (getenv("default-uart-name") == NULL && first_tty != NULL)
		setenv("default-uart-name", first_tty->c_name, 1);

	consoles[c] = NULL;
}

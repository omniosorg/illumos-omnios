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
 * The MMIO UART library contains functionality shared between UART
 * implementations and UART implementation drivers. UART discovery
 * functionality drives the library by inspecting firmware configuration
 * tables, creating driver instances and associating them with MMIO UART
 * instances. The discovery libraries are responsible for locating
 * information needed for each implementation driver, identifying the UART
 * ordering (used to name the UART instances) and identifying the system
 * stdout UART.
 *
 * The library provides top-level hooks called by the console subsystem,
 * wrapping up environment variable management operations and system
 * console avoidance logic.
 */

#include "mmio_uart.h"
#include <stand.h>
#include <bootstrap.h>

extern struct console efi_console;
extern int plat_stdout_is_framebuffer(void);

static bool
mmio_uart_ignore_spcr(struct console *cp)
{
	char *name;
	const char *env;
	bool ignore_spcr = false;

	/*
	 * When we're not firmware-specified we will always ignore the
	 * firmware settings.
	 */
	if (asprintf(&name, "%s-spcr-mode", cp->c_name) > 0) {
		if (getenv(name) == NULL)
			ignore_spcr = true;
		free(name);
	}

	/*
	 * If we are firmware specified we check if we're supposed to
	 * ignore firmware-specified settings.
	 */
	if (!ignore_spcr) {
		/* only check when we do have spcr set */
		env = getenv("ignore-spcr");
		if (env != NULL)
			ignore_spcr = strcmp(env, "true") == 0;
	}

	return (ignore_spcr);
}

static bool
mmio_uart_setup(struct console *cp)
{
	mmio_uart_t *uart = cp->c_private;

	/*
	 * Only touch the hardware if we're ignoring firmware-specified
	 * settings (or there are none). If we have firmware-specified
	 * settings we simply claim that things have worked.
	 */
	if (mmio_uart_ignore_spcr(cp)) {
		if (uart->mu_ops->op_setup(uart)) {
			cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
			return (true);
		}
	} else {
		cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
		return (true);
	}

	return (false);
}

static char *
mmio_uart_asprint_mode(mmio_uart_t *uart)
{
	char par, *buf;
	int dbits, sbits;

	if (uart == NULL)
		return (NULL);

	switch (uart->mu_data_bits) {
	case MMIO_UART_DATA_BITS_8:
		dbits = 8;
		break;
	case MMIO_UART_DATA_BITS_7:
		dbits = 7;
		break;
	case MMIO_UART_DATA_BITS_6:
		dbits = 6;
		break;
	case MMIO_UART_DATA_BITS_5:
		dbits = 5;
		break;
	default:
		dbits = 8;
		break;
	}

	switch (uart->mu_parity) {
	case MMIO_UART_PARITY_EVEN:
		par = 'e';
		break;
	case MMIO_UART_PARITY_ODD:
		par = 'o';
		break;
	case MMIO_UART_PARITY_MARK:
		par = 'm';
		break;
	case MMIO_UART_PARITY_SPACE:
		par = 's';
		break;
	case MMIO_UART_PARITY_NONE:
		par = 'n';
		break;
	default:
		par = 'n';
		break;
	}

	switch (uart->mu_stop_bits) {
	case MMIO_UART_STOP_BITS_2:
		sbits = 2;
		break;
	case MMIO_UART_STOP_BITS_1:
		sbits = 1;
		break;
	case MMIO_UART_STOP_BITS_1_5:
		sbits = 3;
		break;
	default:
		sbits = 1;
		break;
	}

	if (sbits == 3)
		asprintf(&buf, "%lu,%d,%c,1.5,-",
		    uart->mu_speed, dbits, par);
	else
		asprintf(&buf, "%lu,%d,%c,%d,-",
		    uart->mu_speed, dbits, par, sbits);

	return (buf);
}

static int
mmio_uart_parse_mode(mmio_uart_t *uart, const char *value)
{
	unsigned long n;
	mmio_uart_speed_t speed;
	mmio_uart_data_bits_t dbits;
	mmio_uart_parity_t parity;
	mmio_uart_stop_bits_t sbits;

	char *ep;

	if (value == NULL || *value == '\0')
		return (CMD_ERROR);

	errno = 0;
	n = strtoul(value, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);
	speed = (mmio_uart_speed_t)n;

	ep++;
	errno = 0;
	n = strtoul(ep, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);

	switch (n) {
	case 5:
		dbits = MMIO_UART_DATA_BITS_5;
		break;
	case 6:
		dbits = MMIO_UART_DATA_BITS_6;
		break;
	case 7:
		dbits = MMIO_UART_DATA_BITS_7;
		break;
	case 8:
		dbits = MMIO_UART_DATA_BITS_8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n':
		parity = MMIO_UART_PARITY_NONE;
		break;
	case 'e':
		parity = MMIO_UART_PARITY_EVEN;
		break;
	case 'o':
		parity = MMIO_UART_PARITY_ODD;
		break;
	case 'm':
		parity = MMIO_UART_PARITY_MARK;
		break;
	case 's':
		parity = MMIO_UART_PARITY_SPACE;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '1':
		sbits = MMIO_UART_STOP_BITS_1;
		if (ep[0] == '.') {
			if (ep[1] != '5')
				return (CMD_ERROR);
			ep += 2;
			sbits = MMIO_UART_STOP_BITS_1_5;
		}

		break;
	case '2':
		sbits = MMIO_UART_STOP_BITS_2;
		break;
	default:
		return (CMD_ERROR);
	}

	/* handshake is ignored, but we check syntax anyhow */
	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '-':
	case 'h':
	case 's':
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep != '\0')
		return (CMD_ERROR);

	/* only accept the settings if the driver supports them */
	if (!uart->mu_ops->op_config_check(uart, speed, dbits, parity, sbits))
		return (CMD_ERROR);

	uart->mu_speed = speed;
	uart->mu_data_bits = dbits;
	uart->mu_parity = parity;
	uart->mu_stop_bits = sbits;
	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or there is invalid value in mode line.
 */
static int
mmio_uart_mode_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	mmio_uart_t *uart;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	uart = cp->c_private;

	if (mmio_uart_ignore_spcr(cp)) {
		if (mmio_uart_parse_mode(uart, value) == CMD_ERROR) {
			printf("%s: invalid mode: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}
		(void) mmio_uart_setup(cp);
		env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	}

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port or invalid value was used.
 */
static int
mmio_uart_cd_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	mmio_uart_t *uart;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	uart = cp->c_private;

	if (mmio_uart_ignore_spcr(cp)) {
		if (strcmp(value, "true") == 0) {
			uart->mu_ignore_cd = true;
		} else if (strcmp(value, "false") == 0) {
			uart->mu_ignore_cd = false;
		} else {
			printf("%s: invalid value: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}

		(void) mmio_uart_setup(cp);
		env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	}

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or invalid value was used.
 */
static int
mmio_uart_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	mmio_uart_t *uart;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	uart = cp->c_private;

	if (mmio_uart_ignore_spcr(cp)) {
		if (strcmp(value, "true") == 0) {
			uart->mu_rtsdtr_off = true;
		} else if (strcmp(value, "false") == 0) {
			uart->mu_rtsdtr_off = false;
		} else {
			printf("%s: invalid value: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}

		(void) mmio_uart_setup(cp);
		env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	}

	return (CMD_OK);
}

static void
mmio_uart_probe(struct console *cp)
{
	mmio_uart_t	*uart;
	char		*env;

	uart = cp->c_private;

	if (!(uart->mu_flags & MMIO_UART_VALID)) {
		cp->c_flags = 0;
		return;
	}

	if (uart->mu_flags & MMIO_UART_PROBED) {
		cp->c_flags = C_PRESENTIN | C_PRESENTOUT;
		return;
	}

	/*
	 * When this UART has been specified as the system stdout (via
	 * SPCR or FDT's /chosen/stdout-path) we need to tweak the console
	 * variable.
	 */
	if (uart->mu_flags & MMIO_UART_STDOUT) {
		/*
		 * Tweak the consoles list, placing us first if already set.
		 */
		if ((env = getenv("console")) != NULL) {
			char *val;

			if (asprintf(&val, "%s,text", cp->c_name) > 0) {
				setenv("console", val, 1);
				free(val);
			}
		} else {
			setenv("console", cp->c_name, 1);
		}
	}

	cp->c_flags = 0;
	if (mmio_uart_setup(cp))
		cp->c_flags = C_PRESENTIN | C_PRESENTOUT;

	/*
	 * Set the boot console variables, allowing dboot to pick them
	 * up, use the UART and pass the values on to the kernel.
	 */
	if ((uart->mu_flags & MMIO_UART_STDOUT) &&
	    (cp->c_flags = C_PRESENTIN | C_PRESENTOUT) &&
	    (uart->mu_base != 0 && uart->mu_type != 0)) {
		char *val;

		if (asprintf(&val, "0x%lx", uart->mu_base) > 0) {
			setenv("bcons.uart.mmio_base", val, 1);
			free(val);

			if (asprintf(&val, "0x%x", uart->mu_type) > 0) {
				setenv("bcons.uart.type", val, 1);
				free(val);
			}

			setenv("bcons.uart.name", cp->c_name, 1);
		}
	}

	uart->mu_flags |= MMIO_UART_PROBED;
}

static int
mmio_uart_init(struct console *cp, int arg __attribute((unused)))
{
	if (mmio_uart_setup(cp))
		return (CMD_OK);

	cp->c_flags = 0;
	return (CMD_ERROR);
}

static bool
mmio_uart_carrier_ok(struct console *cp)
{
	mmio_uart_t *uart = cp->c_private;

	if (uart->mu_ignore_cd)
		return (true);

	return (uart->mu_ops->op_has_carrier(uart));
}

/*
 * When we're the system stdout and the platform stdout is not the framebuffer
 * we need to suppress the MMIO UART console functionality so as to not
 * interfere with the UEFI console.
 *
 * - If we're not the firmware-identified stdout we do not suppress.
 * - If the platform stdout is the framebuffer we do not suppress.
 * - If the EFI console is inactive we do not suppress.
 * - Failing the above, we suppress.
 */
static bool
mmio_uart_suppress(mmio_uart_t *uart)
{
	if (!(uart->mu_flags & MMIO_UART_STDOUT))
		return (false);

	if (plat_stdout_is_framebuffer())
		return (false);

	if ((efi_console.c_flags & (C_ACTIVEIN | C_ACTIVEOUT)) !=
	    (C_ACTIVEIN | C_ACTIVEOUT))
		return (false);

	return (true);
}

/*
 * For ischar and getchar we defer to the EFI console when we
 * are the firmware-identifier stdout and the EFI console is active.
 *
 * The above logic mirrors what the i86pc code does.
 *
 * Also see `mmio_uart_suppress' (above) for the conditions where we
 * completely suppress the I/O functions.
 *
 * When we're using our driver we also check carrier-detect (when
 * configured to do so), which is another reason I/O could be skipped.
 */

static void
mmio_uart_putchar(struct console *cp, int c)
{
	mmio_uart_t *uart = cp->c_private;

	if (mmio_uart_suppress(uart))
		return;

	if (!mmio_uart_carrier_ok(cp))
		return;

	uart->mu_ops->op_putchar(uart, c);
}

static int
mmio_uart_getchar(struct console *cp)
{
	mmio_uart_t *uart = cp->c_private;

	if (mmio_uart_suppress(uart))
		return (-1);

	if ((uart->mu_flags & MMIO_UART_STDOUT) &&
	    (efi_console.c_flags & C_PRESENTIN))
		return (efi_console.c_in(&efi_console));

	if (!mmio_uart_carrier_ok(cp))
		return (-1);

	return (uart->mu_ops->op_getchar(uart));
}

static int
mmio_uart_ischar(struct console *cp)
{
	mmio_uart_t *uart = cp->c_private;

	if (mmio_uart_suppress(uart))
		return (0);

	if ((uart->mu_flags & MMIO_UART_STDOUT) &&
	    !plat_stdout_is_framebuffer() &&
	    (efi_console.c_flags & C_PRESENTIN))
		return (efi_console.c_ready(&efi_console));

	if (!mmio_uart_carrier_ok(cp))
		return (0);

	return (uart->mu_ops->op_ischar(uart));
}

static int
mmio_uart_ioctl(struct console *cp __attribute((unused)),
    int n __attribute((unused)), void *arg __attribute((unused)))
{
	return (ENOTTY);
}

static void
mmio_uart_devinfo(struct console *cp __attribute((unused)))
{
	mmio_uart_t *uart = cp->c_private;
	uart->mu_ops->op_devinfo(uart);
}

static void
mmio_uart_set_environment(struct console *cp)
{
	char		name[50];
	char		name2[50];
	char		value[30];
	char		*env;
	mmio_uart_t	*uart = cp->c_private;

	uart->mu_ops->op_set_environment(cp);

	if (uart->mu_flags & MMIO_UART_CONFIG_LOCKED) {
		/*
		 * If we're locked to firmware or hardware specified settings
		 * we just update the environment variable to match our current
		 * configuration, overwriting anything that might already exist.
		 *
		 * We set ttyX-spcr-mode to communicate to the rest of loader
		 * that this is a config-specified UART and that the config
		 * should not be changed unless ignore-spcr is also set.
		 */
		snprintf(name, sizeof (name), "%s-mode", cp->c_name);
		snprintf(name2, sizeof (name2), "%s-spcr-mode", cp->c_name);
		unsetenv(name);
		unsetenv(name2);
		if ((env = mmio_uart_asprint_mode(uart)) != NULL) {
			env_setenv(name, EV_VOLATILE, env,
			    mmio_uart_mode_set, env_nounset);
			env_setenv(name2, EV_VOLATILE, env,
			    env_noset, env_nounset);
			free(env);
		}

		snprintf(name, sizeof (name), "%s-ignore-cd", cp->c_name);
		snprintf(value, sizeof (value), "%s",
		    uart->mu_ignore_cd ? "true" : "false");
		unsetenv(name);
		env_setenv(name, EV_VOLATILE, value,
		    mmio_uart_cd_set, env_nounset);

		snprintf(name, sizeof (name), "%s-rts-dtr-off", cp->c_name);
		snprintf(value, sizeof (value), "%s",
		    uart->mu_rtsdtr_off ? "true" : "false");
		unsetenv(name);
		env_setenv(name, EV_VOLATILE, value,
		    mmio_uart_rtsdtr_set, env_nounset);
	} else {
		/*
		 * We're not locked to hardware or firmware.
		 * If a variable not not exist we create it with our current
		 * values. If it already exists we read it and recreate it
		 * with our hook.
		 *
		 * We explicitly clear ttyX-spcr-mode so that we don't
		 * accidentally lock the config.
		 */
		snprintf(name, sizeof (name), "%s-spcr-mode", cp->c_name);
		unsetenv(name);
		snprintf(name, sizeof (name), "%s-mode", cp->c_name);
		if ((env = getenv(name)) == NULL) {
			if ((env = mmio_uart_asprint_mode(uart)) != NULL) {
				env_setenv(name, EV_VOLATILE, env,
				    mmio_uart_mode_set, env_nounset);
				free(env);
			}
		} else {
			env = strdup(env);
			unsetenv(name);
			env_setenv(name, EV_VOLATILE, env,
			    mmio_uart_mode_set, env_nounset);
			free(env);
		}

		snprintf(name, sizeof (name), "%s-ignore-cd", cp->c_name);
		if ((env = getenv(name)) == NULL) {
			snprintf(value, sizeof (value), "%s",
			    uart->mu_ignore_cd ? "true" : "false");
			unsetenv(name);
			env_setenv(name, EV_VOLATILE, value,
			    mmio_uart_cd_set, env_nounset);
		} else {
			env = strdup(env);
			unsetenv(name);
			env_setenv(name, EV_VOLATILE, env,
			    mmio_uart_cd_set, env_nounset);
			free(env);
		}

		snprintf(name, sizeof (name), "%s-rts-dtr-off", cp->c_name);
		if ((env = getenv(name)) == NULL) {
			snprintf(value, sizeof (value), "%s",
			    uart->mu_rtsdtr_off ? "true" : "false");
			unsetenv(name);
			env_setenv(name, EV_VOLATILE, value,
			    mmio_uart_rtsdtr_set, env_nounset);
		} else {
			env = strdup(env);
			unsetenv(name);
			env_setenv(name, EV_VOLATILE, env,
			    mmio_uart_rtsdtr_set, env_nounset);
			free(env);
		}
	}
}

/*
 * Called from the firmware integration UART discovery function to allocate
 * and set up the discovered UART.
 */
struct console *
mmio_uart_make_tty(mmio_uart_t *uart)
{
	struct console *tty;
	uint32_t idx;

	idx = uart->mu_serial_idx;

	if ((tty = malloc(sizeof (*tty))) == NULL)
		return (NULL);

	if (asprintf(&tty->c_name, "tty%c", (int)('a' + idx)) < 0) {
		free(tty);
		return (NULL);
	}

	if (asprintf(&tty->c_desc, "%s", uart->mu_fwname) < 0) {
		free(tty->c_name);
		free(tty);
		return (NULL);
	}

	tty->c_flags = 0;
	tty->c_probe = mmio_uart_probe;
	tty->c_init = mmio_uart_init;
	tty->c_out = mmio_uart_putchar;
	tty->c_in = mmio_uart_getchar;
	tty->c_ready = mmio_uart_ischar;
	tty->c_ioctl = mmio_uart_ioctl;
	tty->c_devinfo = mmio_uart_devinfo;
	tty->c_private = uart;

	if (uart->mu_ops->op_make_tty_hook(uart) != 0) {
		free(tty->c_name);
		free(tty);
		return (NULL);
	}

	mmio_uart_set_environment(tty);

	if (uart->mu_flags & MMIO_UART_STDOUT)
		return (tty);

	/* Reset terminal to initial normal settings with ESC [ 0 m */
	uart->mu_ops->op_putchar(uart, 0x1b);
	uart->mu_ops->op_putchar(uart, '[');
	uart->mu_ops->op_putchar(uart, '0');
	uart->mu_ops->op_putchar(uart, 'm');

	/* drain random data from input */
	while (uart->mu_ops->op_ischar(uart))
		(void) uart->mu_ops->op_getchar(uart);

	return (tty);
}

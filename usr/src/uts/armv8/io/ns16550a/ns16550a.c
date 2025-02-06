/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2023 Oxide Computer Company
 * Copyright 2025 Michael van der Westhuizen
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/strsun.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/policy.h>
#include <sys/platmod.h>
#include <sys/obpdefs.h>
#include "ns16550a.h"

#define UARTDR		0x00
#define UARTRSR		0x04
#define UARTECR		0x04
#define UARTFR		0x18
#define UARTIBRD	0x24
#define UARTFBRD	0x28
#define UARTLCR_H	0x2c
#define UARTCR		0x30
#define UARTIFLS	0x34
#define UARTIMSC	0x38	// interrupt mask set/clear
#define UARTRIS		0x3c	// interrupt raw status register
#define UARTMIS		0x40	// masked interrupt status register
#define UARTICR		0x44	// interrupt clear register

#define REG_READ(ns16550, reg)		ddi_get32((ns16550)->ns16550_iohandle, (uint32_t *)((ns16550)->ns16550_ioaddr + (reg)))
#define REG_WRITE(ns16550, reg, val)	ddi_put32((ns16550)->ns16550_iohandle, (uint32_t *)((ns16550)->ns16550_ioaddr + (reg)), (val))

union uart_dr {
	uint32_t dw;
	struct {
		uint32_t data		: 8;
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 4;
		uint32_t 		: 16;
	};
};

union uart_rsr {
	uint32_t dw;
	struct {
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 4;
		uint32_t 		: 24;
	};
};

union uart_fr {
	uint32_t dw;
	struct {
		uint32_t cts		: 1;
		uint32_t dsr		: 1;
		uint32_t dcd		: 1;
		uint32_t busy		: 1;
		uint32_t rxfe		: 1;
		uint32_t txff		: 1;
		uint32_t rxff		: 1;
		uint32_t txfe		: 1;
		uint32_t ri		: 1;
		uint32_t 		: 7;
		uint32_t 		: 16;
	};
};

union uart_ibrd {
	uint32_t dw;
	struct {
		uint32_t divint		: 16;
		uint32_t 		: 16;
	};
};

union uart_fbrd {
	uint32_t dw;
	struct {
		uint32_t divfrac	: 6;
		uint32_t 		: 26;
	};
};

union uart_lcr_h {
	uint32_t dw;
	struct {
		uint32_t brk		: 1;
		uint32_t pen		: 1;
		uint32_t eps		: 1;
		uint32_t stp2		: 1;
		uint32_t fen		: 1;
		uint32_t wlen		: 2;
		uint32_t sps		: 1;
		uint32_t 		: 8;
		uint32_t 		: 16;
	};
};

union uart_cr {
	uint32_t dw;
	struct {
		uint32_t uarten		: 1;
		uint32_t siren		: 1;
		uint32_t sirlp		: 1;
		uint32_t 		: 4;
		uint32_t lbe		: 1;
		uint32_t txe		: 1;
		uint32_t rxe		: 1;
		uint32_t dtr		: 1;
		uint32_t rts		: 1;
		uint32_t out1		: 1;
		uint32_t out2		: 1;
		uint32_t rtsen		: 1;
		uint32_t ctsen		: 1;
		uint32_t 		: 16;
	};
};

union uart_ifls {
	uint32_t dw;
	struct {
		uint32_t txiflsel	: 3;
		uint32_t rxiflsel	: 3;
		uint32_t 		: 10;
		uint32_t 		: 16;
	};
};

union uart_intr {
	uint32_t dw;
	struct {
		uint32_t ri		: 1;
		uint32_t cts		: 1;
		uint32_t dcd		: 1;
		uint32_t dsr		: 1;
		uint32_t rx		: 1;
		uint32_t tx		: 1;
		uint32_t rt		: 1;
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 5;
		uint32_t 		: 16;
	};
};

#define	NS16550_REGISTER_FILE_NO 0
#define	NS16550_REGOFFSET 0
#define	NS16550_REGISTER_LEN 0
#define	NS16550_DEFAULT_BAUD	B115200

/*
 * set the RX FIFO trigger_level to half the RX FIFO size for now
 * we may want to make this configurable later.
 */
static	int ns16550_trig_level = FIFO_TRIG_8;

static int ns16550_drain_check = 15000000;		/* tunable: exit drain check time */
static int ns16550_min_dtr_low = 500000;		/* tunable: minimum DTR down time */
static int ns16550_min_utbrk = 100000;		/* tunable: minumum untimed brk time */

/*
 * Just in case someone has a chip with broken loopback mode, we provide a
 * means to disable the loopback test. By default, we only loopback test
 * UARTs which look like they have FIFOs bigger than 16 bytes.
 * Set to 0 to suppress test, or to 2 to enable test on any size FIFO.
 */
static int ns16550_fifo_test = 1;		/* tunable: set to 0, 1, or 2 */

/*
 * Allow ability to switch off testing of the scratch register.
 * Some UART emulators might not have it. This will also disable the test
 * for Exar/Startech ST16C650, as that requires use of the SCR register.
 */
static int ns16550_scr_test = 1;		/* tunable: set to 0 to disable SCR reg test */

/*
 * As we don't yet support on-chip flow control, it's a bad idea to put a
 * large number of characters in the TX FIFO, since if other end tells us
 * to stop transmitting, we can only stop filling the TX FIFO, but it will
 * still carry on draining by itself, so remote end still gets what's left
 * in the FIFO.
 */
static int ns16550_max_tx_fifo = 16;	/* tunable: max fill of TX FIFO */

#define	nsasync_stopc	nsasync_ttycommon.t_stopc
#define	nsasync_startc	nsasync_ttycommon.t_startc

#define	NS16550_INIT	1
#define	NS16550_NOINIT	0

/* enum value for sw and hw flow control action */
typedef enum {
	FLOW_CHECK,
	FLOW_STOP,
	FLOW_START
} nsasync_flowc_action;

#ifdef DEBUG
#define	NS16550_DEBUG_INIT	0x0001	/* Output msgs during driver initialization. */
#define	NS16550_DEBUG_INPUT	0x0002	/* Report characters received during int. */
#define	NS16550_DEBUG_EOT	0x0004	/* Output msgs when wait for xmit to finish. */
#define	NS16550_DEBUG_CLOSE	0x0008	/* Output msgs when driver open/close called */
#define	NS16550_DEBUG_HFLOW	0x0010	/* Output msgs when H/W flowcontrol is active */
#define	NS16550_DEBUG_PROCS	0x0020	/* Output each proc name as it is entered. */
#define	NS16550_DEBUG_STATE	0x0040	/* Output value of Interrupt Service Reg. */
#define	NS16550_DEBUG_INTR	0x0080	/* Output value of Interrupt Service Reg. */
#define	NS16550_DEBUG_OUT	0x0100	/* Output msgs about output events. */
#define	NS16550_DEBUG_BUSY	0x0200	/* Output msgs when xmit is enabled/disabled */
#define	NS16550_DEBUG_MODEM	0x0400	/* Output msgs about modem status & control. */
#define	NS16550_DEBUG_MODM2	0x0800	/* Output msgs about modem status & control. */
#define	NS16550_DEBUG_IOCTL	0x1000	/* Output msgs about ioctl messages. */
#define	NS16550_DEBUG_CHIP	0x2000	/* Output msgs about chip identification. */
#define	NS16550_DEBUG_SFLOW	0x4000	/* Output msgs when S/W flowcontrol is active */
#define	NS16550_DEBUG(x) (debug & (x))
static	int debug  = 0;
#else
#define	NS16550_DEBUG(x) B_FALSE
#endif

/* pnpISA compressed device ids */
#define	pnpMTS0219 0xb6930219	/* Multitech MT5634ZTX modem */

/*
 * PPS (Pulse Per Second) support.
 */
void ddi_hardpps(struct timeval *, int);
/*
 * This is protected by the ns16550_excl_hi of the port on which PPS event
 * handling is enabled.  Note that only one port should have this enabled at
 * any one time.  Enabling PPS handling on multiple ports will result in
 * unpredictable (but benign) results.
 */
static struct ppsclockev ns16550_ppsev;

#ifdef PPSCLOCKLED
/* XXX Use these to observe PPS latencies and jitter on a scope */
#define	LED_ON
#define	LED_OFF
#else
#define	LED_ON
#define	LED_OFF
#endif

static	int max_ns16550_instance = -1;

static	uint_t	ns16550softintr(caddr_t intarg);
static	uint_t	ns16550intr(caddr_t argns16550);

static boolean_t abort_charseq_recognize(uchar_t ch);

/* The async interrupt entry points */
static void	nsasync_txint(struct ns16550com *ns16550);
static void	nsasync_rxint(struct ns16550com *ns16550, uchar_t lsr);
static void	nsasync_msint(struct ns16550com *ns16550);
static void	nsasync_softint(struct ns16550com *ns16550);

static void	nsasync_ioctl(struct nsasyncline *nsasync, queue_t *q, mblk_t *mp);
static void	nsasync_reioctl(void *unit);
static void	nsasync_iocdata(queue_t *q, mblk_t *mp);
static void	nsasync_restart(void *arg);
static void	nsasync_start(struct nsasyncline *nsasync);
static void	nsasync_nstart(struct nsasyncline *nsasync, int mode);
static void	nsasync_resume(struct nsasyncline *nsasync);
static void	ns16550_program(struct ns16550com *ns16550, int mode);
static void	ns16550init(struct ns16550com *ns16550);
static void	ns16550_waiteot(struct ns16550com *ns16550);
static void	ns16550putchar(cons_polledio_arg_t, uchar_t c);
static int	ns16550getchar(cons_polledio_arg_t);
static boolean_t	ns16550ischar(cons_polledio_arg_t);

static int	ns16550mctl(struct ns16550com *, int, int);
static int	ns16550todm(int, int);
static int	dmtons16550(int);
/*PRINTFLIKE2*/
static void	ns16550error(int level, const char *fmt, ...) __KPRINTFLIKE(2);
static void	ns16550_parse_mode(dev_info_t *devi, struct ns16550com *ns16550);
static void	ns16550_soft_state_free(struct ns16550com *);
static char	*ns16550_hw_name(struct ns16550com *ns16550);
static void	nsasync_hold_utbrk(void *arg);
static void	nsasync_resume_utbrk(struct nsasyncline *nsasync);
static void	nsasync_dtr_free(struct nsasyncline *nsasync);
static int	ns16550_getproperty(dev_info_t *devi, struct ns16550com *ns16550,
		    const char *property);
static boolean_t	nsasync_flowcontrol_sw_input(struct ns16550com *ns16550,
			    nsasync_flowc_action onoff, int type);
static void	nsasync_flowcontrol_sw_output(struct ns16550com *ns16550,
		    nsasync_flowc_action onoff);
static void	nsasync_flowcontrol_hw_input(struct ns16550com *ns16550,
		    nsasync_flowc_action onoff, int type);
static void	nsasync_flowcontrol_hw_output(struct ns16550com *ns16550,
		    nsasync_flowc_action onoff);

#define	GET_PROP(devi, pname, pflag, pval, plen) \
		(ddi_prop_op(DDI_DEV_T_ANY, (devi), PROP_LEN_AND_VAL_BUF, \
		(pflag), (pname), (caddr_t)(pval), (plen)))

static kmutex_t ns16550_glob_lock; /* lock protecting global data manipulation */
static void *ns16550_soft_state;

#ifdef	DEBUG
/*
 * Set this to true to make the driver pretend to do a suspend.  Useful
 * for debugging suspend/resume code with a serial debugger.
 */
static boolean_t	ns16550_nosuspend = B_FALSE;
#endif


static int baudtable[] = {
	0,	/* 0 baud rate */
	50,	/* 50 baud rate */
	75,	/* 75 baud rate */
	110,	/* 110 baud rate */
	134,	/* 134 baud rate */
	150,	/* 150 baud rate */
	200,	/* 200 baud rate */
	300,	/* 300 baud rate */
	600,	/* 600 baud rate */
	1200,	/* 1200 baud rate */
	1800,	/* 1800 baud rate */
	2400,	/* 2400 baud rate */
	4800,	/* 4800 baud rate */
	9600,	/* 9600 baud rate */
	19200,	/* 19200 baud rate */
	38400,	/* 38400 baud rate */
	57600,	/* 57600 baud rate */
	76800,	/* 76800 baud rate */
	115200,	/* 115200 baud rate */
	153600,	/* 153600 baud rate */
	230400,	/* 230400 baud rate */
	307200,	/* 307200 baud rate */
	460800	/* 460800 baud rate */
};

#define	N_SU_SPEEDS	(sizeof (baudtable)/sizeof (baudtable[0]))

static void
ns16550_reset_fifo(struct ns16550com *ns16550, uint8_t flush)
{
}

static void
ns16550_put_char(struct ns16550com *ns16550, uint8_t val)
{
	union uart_dr reg = {0};
	reg.data = val;
	REG_WRITE(ns16550, UARTDR, reg.dw);
}

static boolean_t
ns16550_is_busy(struct ns16550com *ns16550)
{
	union uart_fr reg;
	reg.dw = REG_READ(ns16550, UARTFR);
	return !reg.txfe || reg.busy;
}

static boolean_t
ns16550_tx_is_ready(struct ns16550com *ns16550)
{
	union uart_fr reg;
	reg.dw = REG_READ(ns16550, UARTFR);
	return reg.txff == 0;
}

static boolean_t
ns16550_rx_is_ready(struct ns16550com *ns16550)
{
	union uart_fr reg;
	reg.dw = REG_READ(ns16550, UARTFR);
	return !reg.rxfe;
}

static uint8_t
ns16550_get_msr(struct ns16550com *ns16550)
{
	union uart_fr reg;
	reg.dw = REG_READ(ns16550, UARTFR);
	uint8_t ret = 0;
	if (reg.cts)
		ret |= CTS;
	if (reg.dsr)
		ret |= DSR;
	if (reg.dcd)
		ret |= DCD;
	if (reg.ri)
		ret |= RI;
	return ret;
}

static void
ns16550_set_mcr(struct ns16550com *ns16550, uint8_t mcr)
{
	union uart_cr reg;
	reg.dw = REG_READ(ns16550, UARTCR);
	reg.dtr = ((mcr & DTR)? 1: 0);
	reg.rts = ((mcr & RTS)? 1: 0);
	reg.out1 = ((mcr & OUT1)? 1: 0);
	reg.out2 = ((mcr & OUT2)? 1: 0);
	reg.lbe = ((mcr & NS16550_LOOP)? 1: 0);
	REG_WRITE(ns16550, UARTCR, reg.dw);
}

static uint8_t
ns16550_get_mcr(struct ns16550com *ns16550)
{
	union uart_cr reg;
	reg.dw = REG_READ(ns16550, UARTCR);
	uint8_t ret = 0;
	if (reg.dtr)
		ret |= DTR;
	if (reg.rts)
		ret |= RTS;
	if (reg.out1)
		ret |= OUT1;
	if (reg.out2)
		ret |= OUT2;
	if (reg.lbe)
		ret |= NS16550_LOOP;
	return ret;
}

static void
ns16550_set_icr(struct ns16550com *ns16550, uint8_t icr, uint8_t mask)
{
	union uart_intr reg;
	reg.dw = REG_READ(ns16550, UARTIMSC);
	if (mask & RIEN) {
		reg.rx = ((icr & RIEN)? 1: 0);
		reg.rt = ((icr & RIEN)? 1: 0);
	}
	if (mask & TIEN) {
		reg.tx = ((icr & TIEN)? 1: 0);
	}
	if (mask & MIEN) {
		reg.ri =  ((icr & MIEN)? 1: 0);
		reg.cts = ((icr & MIEN)? 1: 0);
		reg.dcd = ((icr & MIEN)? 1: 0);
		reg.dsr = ((icr & MIEN)? 1: 0);
	}
	REG_WRITE(ns16550, UARTIMSC, reg.dw);
}

static uint8_t
ns16550_get_icr(struct ns16550com *ns16550)
{
	union uart_intr reg;
	reg.dw = REG_READ(ns16550, UARTIMSC);
	uint8_t ret = 0;
	if (reg.rx)
		ret |= RIEN;
	if (reg.tx)
		ret |= TIEN;
	if (reg.ri || reg.cts || reg.dcd || reg.dsr)
		ret |= MIEN;
	return ret;
}

static uint8_t
ns16550_get_lsr(struct ns16550com *ns16550)
{
	union uart_rsr rsr;
	rsr.dw = REG_READ(ns16550, UARTRSR);
	uint8_t ret = 0;
	if (rsr.fe)
		ret |= FRMERR;
	if (rsr.pe)
		ret |= PARERR;
	if (rsr.be)
		ret |= BRKDET;
	if (rsr.oe)
		ret |= OVRRUN;
	REG_WRITE(ns16550, UARTECR, 0);

	union uart_fr fr;
	fr.dw = REG_READ(ns16550, UARTFR);
	if (fr.txfe) {
		ret |= XHRE;
		if (!fr.busy)
			ret |= XSRE;
	}
	if (!fr.rxfe)
		ret |= RCA;
	return ret;
}

static uint8_t
ns16550_get_char(struct ns16550com *ns16550)
{
	union uart_dr reg;
	reg.dw = REG_READ(ns16550, UARTDR);
	return reg.data;
}

static void
ns16550_set_lcr(struct ns16550com *ns16550, uint8_t lcr)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(ns16550, UARTLCR_H);

	reg.pen = ((lcr & PEN)? 1: 0);
	reg.eps = ((lcr & EPS)? 1: 0);

	switch (lcr & (WLS0 | WLS1)) {
	case BITS5: reg.wlen = 0; break;
	case BITS6: reg.wlen = 1; break;
	case BITS7: reg.wlen = 2; break;
	case BITS8: reg.wlen = 3; break;
	}
	reg.stp2 = ((lcr & STB)? 1: 0);
	reg.brk = ((lcr & SETBREAK)? 1: 0);
	REG_WRITE(ns16550, UARTLCR_H, reg.dw);
}

static void
ns16550_set_break(struct ns16550com *ns16550, boolean_t on)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(ns16550, UARTLCR_H);
	reg.brk = (on? 1: 0);
	REG_WRITE(ns16550, UARTLCR_H, reg.dw);
}

static uint8_t
ns16550_get_lcr(struct ns16550com *ns16550)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(ns16550, UARTLCR_H);

	uint8_t ret = 0;
	if (reg.pen)
		ret |= PEN;
	if (reg.eps)
		ret |= EPS;
	switch (reg.wlen) {
	case 0: ret |= BITS5; break;
	case 1: ret |= BITS6; break;
	case 2: ret |= BITS7; break;
	case 3: ret |= BITS8; break;
	}
	if (reg.stp2)
		ret |= STB;
	if (reg.brk)
		ret |= SETBREAK;
	return ret;
}

static uint8_t
ns16550_get_isr(struct ns16550com *ns16550)
{
	union uart_intr reg;
	reg.dw = REG_READ(ns16550, UARTRIS);
	if (reg.fe || reg.pe || reg.be || reg.oe) {
		reg.dw = 0;
		reg.fe = 1;
		reg.pe = 1;
		reg.be = 1;
		reg.oe = 1;
		REG_WRITE(ns16550, UARTICR, reg.dw);
		return RSTATUS;
	}
	if (reg.rx) {
		reg.dw = 0;
		reg.rx = 1;
		REG_WRITE(ns16550, UARTICR, reg.dw);
		return RxRDY;
	}
	if (reg.rt) {
		reg.dw = 0;
		reg.rt = 1;
		REG_WRITE(ns16550, UARTICR, reg.dw);
		return FFTMOUT;
	}
	if (reg.tx) {
		reg.dw = 0;
		reg.tx = 1;
		REG_WRITE(ns16550, UARTICR, reg.dw);
		return TxRDY;
	}
	if (reg.ri || reg.cts || reg.dcd || reg.dsr) {
		reg.dw = 0;
		reg.ri = 1;
		reg.cts = 1;
		reg.dcd = 1;
		reg.dsr = 1;
		REG_WRITE(ns16550, UARTICR, reg.dw);
		return MSTATUS;
	}
	return NOINTERRUPT;
}

static void
ns16550_reset(struct ns16550com *ns16550)
{
	REG_WRITE(ns16550, UARTCR, 0);
	REG_WRITE(ns16550, UARTECR, 0);
	REG_WRITE(ns16550, UARTIMSC, 0);
	REG_WRITE(ns16550, UARTICR, 0xffff);

	union uart_ifls ifls = {0};
	ifls.txiflsel = 2;	// 1/2
	ifls.rxiflsel = 0;	// 1/8
	REG_WRITE(ns16550, UARTIFLS, ifls.dw);

	union uart_cr cr = {0};
	cr.uarten = 1;
	cr.txe = 1;
	cr.rxe = 1;
	REG_WRITE(ns16550, UARTCR, cr.dw);

	union uart_lcr_h lcr_h = {0};
	lcr_h.fen = 1;
	lcr_h.wlen = 3;
	REG_WRITE(ns16550, UARTLCR_H, lcr_h.dw);
}

static void
ns16550_set_baud(struct ns16550com *ns16550, uint8_t bidx)
{
	ASSERT(bidx < N_SU_SPEEDS);
	int baudrate;
	if (bidx == 0)
		baudrate = 115200;
	else
		baudrate = baudtable[bidx];

	uint32_t bauddiv = (ns16550->ns16550_clock * 4 + baudrate / 2) / baudrate;

	uint32_t cr = REG_READ(ns16550, UARTCR);
	REG_WRITE(ns16550, UARTCR, 0);

	union uart_ibrd ibrd = {0};
	union uart_fbrd fbrd = {0};
	ibrd.divint = bauddiv >> 6;
	fbrd.divfrac = bauddiv & 0x3f;

	REG_WRITE(ns16550, UARTIBRD, ibrd.dw);
	REG_WRITE(ns16550, UARTFBRD, fbrd.dw);
	REG_WRITE(ns16550, UARTCR, cr);
}

static int ns16550rsrv(queue_t *q);
static int ns16550open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr);
static int ns16550close(queue_t *q, int flag, cred_t *credp);
static int ns16550wputdo(queue_t *q, mblk_t *mp, boolean_t);
static int ns16550wput(queue_t *q, mblk_t *mp);

struct module_info ns16550_info = {
	0,
	"ns16550a",
	0,
	INFPSZ,
	4096,
	128
};

static struct qinit ns16550_rint = {
	putq,
	ns16550rsrv,
	ns16550open,
	ns16550close,
	NULL,
	&ns16550_info,
	NULL
};

static struct qinit ns16550_wint = {
	ns16550wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&ns16550_info,
	NULL
};

struct streamtab ns16550_str_info = {
	&ns16550_rint,
	&ns16550_wint,
	NULL,
	NULL
};

static int ns16550info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int ns16550probe(dev_info_t *);
static int ns16550attach(dev_info_t *, ddi_attach_cmd_t);
static int ns16550detach(dev_info_t *, ddi_detach_cmd_t);
static int ns16550quiesce(dev_info_t *);

static 	struct cb_ops cb_ns16550_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&ns16550_str_info,		/* cb_stream */
	D_MP			/* cb_flag */
};

struct dev_ops ns16550_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ns16550info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	ns16550probe,		/* devo_probe */
	ns16550attach,		/* devo_attach */
	ns16550detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_ns16550_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power */
	ns16550quiesce,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"NS16550 driver",
	&ns16550_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int i;

	i = ddi_soft_state_init(&ns16550_soft_state, sizeof (struct ns16550com), 2);
	if (i == 0) {
		mutex_init(&ns16550_glob_lock, NULL, MUTEX_DRIVER, NULL);
		if ((i = mod_install(&modlinkage)) != 0) {
			mutex_destroy(&ns16550_glob_lock);
			ddi_soft_state_fini(&ns16550_soft_state);
		} else {
			DEBUGCONT2(NS16550_DEBUG_INIT, "%s, debug = %x\n",
			    modldrv.drv_linkinfo, debug);
		}
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&modlinkage)) == 0) {
		DEBUGCONT1(NS16550_DEBUG_INIT, "%s unloading\n",
		    modldrv.drv_linkinfo);
		ASSERT(max_ns16550_instance == -1);
		mutex_destroy(&ns16550_glob_lock);
		ddi_soft_state_fini(&ns16550_soft_state);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

void
nsasync_put_suspq(struct ns16550com *ns16550, mblk_t *mp)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;

	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	if (nsasync->nsasync_suspqf == NULL)
		nsasync->nsasync_suspqf = mp;
	else
		nsasync->nsasync_suspqb->b_next = mp;

	nsasync->nsasync_suspqb = mp;
}

static mblk_t *
nsasync_get_suspq(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	if ((mp = nsasync->nsasync_suspqf) != NULL) {
		nsasync->nsasync_suspqf = mp->b_next;
		mp->b_next = NULL;
	} else {
		nsasync->nsasync_suspqb = NULL;
	}
	return (mp);
}

static void
nsasync_process_suspq(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	while ((mp = nsasync_get_suspq(ns16550)) != NULL) {
		queue_t *q;

		q = nsasync->nsasync_ttycommon.t_writeq;
		ASSERT(q != NULL);
		mutex_exit(&ns16550->ns16550_excl);
		(void) ns16550wputdo(q, mp, B_FALSE);
		mutex_enter(&ns16550->ns16550_excl);
	}
	nsasync->nsasync_flags &= ~NSASYNC_DDI_SUSPENDED;
	cv_broadcast(&nsasync->nsasync_flags_cv);
}

static int
ns16550detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct ns16550com *ns16550;
	struct nsasyncline *nsasync;

	instance = ddi_get_instance(devi);	/* find out which unit */

	ns16550 = ddi_get_soft_state(ns16550_soft_state, instance);
	if (ns16550 == NULL)
		return (DDI_FAILURE);
	nsasync = ns16550->ns16550_priv;

	switch (cmd) {
	case DDI_DETACH:
		DEBUGNOTE2(NS16550_DEBUG_INIT, "ns16550%d: %s shutdown.",
		    instance, ns16550_hw_name(ns16550));

		/* cancel DTR hold timeout */
		if (nsasync->nsasync_dtrtid != 0) {
			(void) untimeout(nsasync->nsasync_dtrtid);
			nsasync->nsasync_dtrtid = 0;
		}

		/* remove all minor device node(s) for this device */
		ddi_remove_minor_node(devi, NULL);

		mutex_destroy(&ns16550->ns16550_excl);
		mutex_destroy(&ns16550->ns16550_excl_hi);
		cv_destroy(&nsasync->nsasync_flags_cv);
		ddi_remove_intr(devi, 0, ns16550->ns16550_iblock);
		ddi_regs_map_free(&ns16550->ns16550_iohandle);
		ddi_remove_softintr(ns16550->ns16550_softintr_id);
		mutex_destroy(&ns16550->ns16550_soft_lock);
		ns16550_soft_state_free(ns16550);
		DEBUGNOTE1(NS16550_DEBUG_INIT, "ns16550%d: shutdown complete",
		    instance);
		break;
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/* Check the device is not disabled  */
static int
ns16550probe(dev_info_t *dip)
{
	char *buf;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    OBP_STATUS, &buf) != DDI_SUCCESS) {
		return (DDI_PROBE_SUCCESS);
	}

	if (strcmp(buf, "ok") != 0 && strcmp(buf, "okay") != 0) {
		ddi_prop_free(buf);
		return (DDI_PROBE_FAILURE);
	}

	ddi_prop_free(buf);
	return (DDI_PROBE_SUCCESS);
}

static int
ns16550attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	int mcr;
	int ret;
	int i;
	struct ns16550com *ns16550;
	char name[NS16550_MINOR_LEN];
	int status;
	static ddi_device_acc_attr_t ioattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};

	instance = ddi_get_instance(devi);	/* find out which unit */

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	uint_t uart_clock = 48000000;
	struct prom_hwclock hwclock;
	if (prom_get_clock_by_name(ddi_get_nodeid(devi), "uartclk", &hwclock) == 0) {
		int err = -1;
		if (&plat_hwclock_get_rate)
			err = plat_hwclock_get_rate(&hwclock);
		if (err > 0)
			uart_clock = err;
	}

	ret = ddi_soft_state_zalloc(ns16550_soft_state, instance);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	ns16550 = ddi_get_soft_state(ns16550_soft_state, instance);
	ASSERT(ns16550 != NULL);	/* can't fail - we only just allocated it */
	ns16550->ns16550_unit = instance;
	mutex_enter(&ns16550_glob_lock);
	if (instance > max_ns16550_instance)
		max_ns16550_instance = instance;
	mutex_exit(&ns16550_glob_lock);

	ns16550->ns16550_clock = uart_clock;

	if (ddi_regs_map_setup(devi, NS16550_REGISTER_FILE_NO, (caddr_t *)&ns16550->ns16550_ioaddr,
	    NS16550_REGOFFSET, NS16550_REGISTER_LEN, &ioattr, &ns16550->ns16550_iohandle)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ns16550%d: could not map UART registers @ %p",
		    instance, (void *)ns16550->ns16550_ioaddr);

		ns16550_soft_state_free(ns16550);
		return (DDI_FAILURE);
	}

	DEBUGCONT2(NS16550_DEBUG_INIT, "ns16550%dattach: UART @ %p\n",
	    instance, (void *)ns16550->ns16550_ioaddr);

	ns16550->ns16550_com_port = instance + 1;

	/*
	 * It appears that there was async hardware that on reset
	 * did not clear ICR.  Hence when we get to
	 * ddi_get_iblock_cookie below, this hardware would cause
	 * the system to hang if there was input available.
	 */

	ns16550_set_icr(ns16550, 0, 0xff);

	/* establish default usage */
	ns16550->ns16550_mcr |= RTS|DTR;		/* do use RTS/DTR after open */
	ns16550->ns16550_lcr = STOP1|BITS8;		/* default to 1 stop 8 bits */
	ns16550->ns16550_bidx = NS16550_DEFAULT_BAUD;	/* default to 9600  */
#ifdef DEBUG
	ns16550->ns16550_msint_cnt = 0;			/* # of times in nsasync_msint */
#endif
	mcr = 0;				/* don't enable until open */

	/*
	 * For motherboard ports, emulate tty eeprom properties.
	 * Actually, we can't tell if a port is motherboard or not,
	 * so for "motherboard ports", read standard DOS COM ports.
	 */
	switch (ns16550_getproperty(devi, ns16550, "ignore-cd")) {
	case 0:				/* *-ignore-cd=False */
		DEBUGCONT1(NS16550_DEBUG_MODEM,
		    "ns16550%dattach: clear NS16550_IGNORE_CD\n", instance);
		ns16550->ns16550_flags &= ~NS16550_IGNORE_CD; /* wait for cd */
		break;
	case 1:				/* *-ignore-cd=True */
		/*FALLTHRU*/
	default:			/* *-ignore-cd not defined */
		/*
		 * We set rather silly defaults of soft carrier on
		 * and DTR/RTS raised here because it might be that
		 * one of the motherboard ports is the system console.
		 */
		DEBUGCONT1(NS16550_DEBUG_MODEM,
		    "ns16550%dattach: set NS16550_IGNORE_CD, set RTS & DTR\n",
		    instance);
		mcr = ns16550->ns16550_mcr;		/* rts/dtr on */
		ns16550->ns16550_flags |= NS16550_IGNORE_CD;	/* ignore cd */
		break;
	}

	/* Property for not raising DTR/RTS */
	switch (ns16550_getproperty(devi, ns16550, "rts-dtr-off")) {
	case 0:				/* *-rts-dtr-off=False */
		ns16550->ns16550_flags |= NS16550_RTS_DTR_OFF;	/* OFF */
		mcr = ns16550->ns16550_mcr;		/* rts/dtr on */
		DEBUGCONT1(NS16550_DEBUG_MODEM, "ns16550%dattach: "
		    "NS16550_RTS_DTR_OFF set and DTR & RTS set\n",
		    instance);
		break;
	case 1:				/* *-rts-dtr-off=True */
		/*FALLTHRU*/
	default:			/* *-rts-dtr-off undefined */
		break;
	}

	/* Parse property for tty modes */
	ns16550_parse_mode(devi, ns16550);

	/*
	 * Get icookie for mutexes initialization
	 */
	if ((ddi_get_iblock_cookie(devi, 0, &ns16550->ns16550_iblock) !=
	    DDI_SUCCESS) ||
	    (ddi_get_soft_iblock_cookie(devi, DDI_SOFTINT_MED,
	    &ns16550->ns16550_soft_iblock) != DDI_SUCCESS)) {
		ddi_regs_map_free(&ns16550->ns16550_iohandle);
		cmn_err(CE_CONT,
		    "ns16550%d: could not hook interrupt for UART @ %p\n",
		    instance, (void *)ns16550->ns16550_ioaddr);
		ns16550_soft_state_free(ns16550);
		return (DDI_FAILURE);
	}

	/*
	 * Initialize mutexes before accessing the hardware
	 */
	mutex_init(&ns16550->ns16550_soft_lock, NULL, MUTEX_DRIVER,
	    (void *)ns16550->ns16550_soft_iblock);
	mutex_init(&ns16550->ns16550_excl, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ns16550->ns16550_excl_hi, NULL, MUTEX_DRIVER,
	    (void *)ns16550->ns16550_iblock);
	mutex_init(&ns16550->ns16550_soft_sr, NULL, MUTEX_DRIVER,
	    (void *)ns16550->ns16550_soft_iblock);
	mutex_enter(&ns16550->ns16550_excl);
	mutex_enter(&ns16550->ns16550_excl_hi);

	/* Make UART type visible in device tree for prtconf, etc */
	dev_t dev = makedevice(DDI_MAJOR_T_UNKNOWN, ns16550->ns16550_unit);
	ddi_prop_update_string(dev, devi, "uart", ns16550_hw_name(ns16550));

	ns16550_reset(ns16550);

	/* Set the baud rate to 9600 */
	ns16550_set_baud(ns16550, ns16550->ns16550_bidx);
	ns16550_set_lcr(ns16550, ns16550->ns16550_lcr);
	ns16550_set_mcr(ns16550, mcr);

	mutex_exit(&ns16550->ns16550_excl_hi);
	mutex_exit(&ns16550->ns16550_excl);

	/*
	 * Set up the other components of the ns16550com structure for this port.
	 */
	ns16550->ns16550_dip = devi;

	/*
	 * Install per instance software interrupt handler.
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_MED,
	    &(ns16550->ns16550_softintr_id), NULL, 0, ns16550softintr,
	    (caddr_t)ns16550) != DDI_SUCCESS) {
		mutex_destroy(&ns16550->ns16550_soft_lock);
		mutex_destroy(&ns16550->ns16550_excl);
		mutex_destroy(&ns16550->ns16550_excl_hi);
		ddi_regs_map_free(&ns16550->ns16550_iohandle);
		cmn_err(CE_CONT,
		    "Can not set soft interrupt for NS16550 driver\n");
		ns16550_soft_state_free(ns16550);
		return (DDI_FAILURE);
	}

	mutex_enter(&ns16550->ns16550_excl);
	mutex_enter(&ns16550->ns16550_excl_hi);

	/*
	 * Install interrupt handler for this device.
	 */
	if (ddi_add_intr(devi, 0, NULL, 0, ns16550intr,
	    (caddr_t)ns16550) != DDI_SUCCESS) {
		mutex_exit(&ns16550->ns16550_excl_hi);
		mutex_exit(&ns16550->ns16550_excl);
		ddi_remove_softintr(ns16550->ns16550_softintr_id);
		mutex_destroy(&ns16550->ns16550_soft_lock);
		mutex_destroy(&ns16550->ns16550_excl);
		mutex_destroy(&ns16550->ns16550_excl_hi);
		ddi_regs_map_free(&ns16550->ns16550_iohandle);
		cmn_err(CE_CONT,
		    "Can not set device interrupt for NS16550 driver\n");
		ns16550_soft_state_free(ns16550);
		return (DDI_FAILURE);
	}

	mutex_exit(&ns16550->ns16550_excl_hi);
	mutex_exit(&ns16550->ns16550_excl);

	ns16550init(ns16550);	/* initialize the nsasyncline structure */

	/* create minor device nodes for this device */
	/*
	 * For DOS COM ports, add letter suffix so
	 * devfsadm can create correct link names.
	 */
	name[0] = ns16550->ns16550_com_port + 'a' - 1;
	name[1] = '\0';
	status = ddi_create_minor_node(devi, name, S_IFCHR, instance,
	    ns16550->ns16550_com_port != 0 ? DDI_NT_SERIAL_MB : DDI_NT_SERIAL, 0);
	if (status == DDI_SUCCESS) {
		(void) strcat(name, ",cu");
		status = ddi_create_minor_node(devi, name, S_IFCHR,
		    OUTLINE | instance,
		    ns16550->ns16550_com_port != 0 ? DDI_NT_SERIAL_MB_DO :
		    DDI_NT_SERIAL_DO, 0);
	}

	if (status != DDI_SUCCESS) {
		struct nsasyncline *nsasync = ns16550->ns16550_priv;

		ddi_remove_minor_node(devi, NULL);
		ddi_remove_intr(devi, 0, ns16550->ns16550_iblock);
		ddi_remove_softintr(ns16550->ns16550_softintr_id);
		mutex_destroy(&ns16550->ns16550_soft_lock);
		mutex_destroy(&ns16550->ns16550_excl);
		mutex_destroy(&ns16550->ns16550_excl_hi);
		cv_destroy(&nsasync->nsasync_flags_cv);
		ddi_regs_map_free(&ns16550->ns16550_iohandle);
		ns16550_soft_state_free(ns16550);
		return (DDI_FAILURE);
	}

	/*
	 * Fill in the polled I/O structure.
	 */
	ns16550->polledio.cons_polledio_version = CONSPOLLEDIO_V0;
	ns16550->polledio.cons_polledio_argument = (cons_polledio_arg_t)ns16550;
	ns16550->polledio.cons_polledio_putchar = ns16550putchar;
	ns16550->polledio.cons_polledio_getchar = ns16550getchar;
	ns16550->polledio.cons_polledio_ischar = ns16550ischar;
	ns16550->polledio.cons_polledio_enter = NULL;
	ns16550->polledio.cons_polledio_exit = NULL;

	ddi_report_dev(devi);
	DEBUGCONT1(NS16550_DEBUG_INIT, "ns16550%dattach: done\n", instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
ns16550info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	dev_t dev = (dev_t)arg;
	int instance, error;
	struct ns16550com *ns16550;

	instance = UNIT(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		ns16550 = ddi_get_soft_state(ns16550_soft_state, instance);
		if ((ns16550 == NULL) || (ns16550->ns16550_dip == NULL))
			error = DDI_FAILURE;
		else {
			*result = (void *) ns16550->ns16550_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/* ns16550_getproperty -- walk through all name variants until we find a match */

static int
ns16550_getproperty(dev_info_t *devi, struct ns16550com *ns16550, const char *property)
{
	int len;
	int ret;
	char letter = ns16550->ns16550_com_port + 'a' - 1;	/* for ttya */
	char number = ns16550->ns16550_com_port + '0';		/* for COM1 */
	char val[40];
	char name[40];

	/* Property for ignoring DCD */
	(void) sprintf(name, "tty%c-%s", letter, property);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "tty0%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "port-%c-%s", letter, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS)
		return (-1);		/* property non-existant */
	if (val[0] == 'f' || val[0] == 'F' || val[0] == '0')
		return (0);		/* property false/0 */
	return (1);			/* property true/!0 */
}

/* ns16550_soft_state_free - local wrapper for ddi_soft_state_free(9F) */

static void
ns16550_soft_state_free(struct ns16550com *ns16550)
{
	mutex_enter(&ns16550_glob_lock);
	/* If we were the max_ns16550_instance, work out new value */
	if (ns16550->ns16550_unit == max_ns16550_instance) {
		while (--max_ns16550_instance >= 0) {
			if (ddi_get_soft_state(ns16550_soft_state,
			    max_ns16550_instance) != NULL)
				break;
		}
	}
	mutex_exit(&ns16550_glob_lock);

	if (ns16550->ns16550_priv != NULL) {
		kmem_free(ns16550->ns16550_priv, sizeof (struct nsasyncline));
		ns16550->ns16550_priv = NULL;
	}
	ddi_soft_state_free(ns16550_soft_state, ns16550->ns16550_unit);
}

static char *
ns16550_hw_name(struct ns16550com *ns16550)
{
	return "PL011";
}

/*
 * ns16550init() initializes the TTY protocol-private data for this channel
 * before enabling the interrupts.
 */
static void
ns16550init(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync;

	ns16550->ns16550_priv = kmem_zalloc(sizeof (struct nsasyncline), KM_SLEEP);
	nsasync = ns16550->ns16550_priv;
	mutex_enter(&ns16550->ns16550_excl);
	nsasync->nsasync_common = ns16550;
	cv_init(&nsasync->nsasync_flags_cv, NULL, CV_DRIVER, NULL);
	mutex_exit(&ns16550->ns16550_excl);
}

/*ARGSUSED3*/
static int
ns16550open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	struct ns16550com	*ns16550;
	struct nsasyncline *nsasync;
	int		mcr;
	int		unit;
	int 		len;
	struct termios 	*termiosp;

	unit = UNIT(*dev);
	DEBUGCONT1(NS16550_DEBUG_CLOSE, "ns16550%dopen\n", unit);
	ns16550 = ddi_get_soft_state(ns16550_soft_state, unit);
	if (ns16550 == NULL)
		return (ENXIO);		/* unit not configured */
	nsasync = ns16550->ns16550_priv;
	mutex_enter(&ns16550->ns16550_excl);

again:
	mutex_enter(&ns16550->ns16550_excl_hi);

	/*
	 * Block waiting for carrier to come up, unless this is a no-delay open.
	 */
	if (!(nsasync->nsasync_flags & NSASYNC_ISOPEN)) {
		/*
		 * Set the default termios settings (cflag).
		 * Others are set in ldterm.
		 */
		mutex_exit(&ns16550->ns16550_excl_hi);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(),
		    0, "ttymodes",
		    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
		    len == sizeof (struct termios)) {
			nsasync->nsasync_ttycommon.t_cflag = termiosp->c_cflag;
			kmem_free(termiosp, len);
		} else {
			cmn_err(CE_WARN,
			    "ns16550: couldn't get ttymodes property!");
		}
#pragma GCC diagnostic pop
		mutex_enter(&ns16550->ns16550_excl_hi);

		/* eeprom mode support - respect properties */
		if (ns16550->ns16550_cflag)
			nsasync->nsasync_ttycommon.t_cflag = ns16550->ns16550_cflag;

		nsasync->nsasync_ttycommon.t_iflag = 0;
		nsasync->nsasync_ttycommon.t_iocpending = NULL;
		nsasync->nsasync_ttycommon.t_size.ws_row = 0;
		nsasync->nsasync_ttycommon.t_size.ws_col = 0;
		nsasync->nsasync_ttycommon.t_size.ws_xpixel = 0;
		nsasync->nsasync_ttycommon.t_size.ws_ypixel = 0;
		nsasync->nsasync_dev = *dev;
		nsasync->nsasync_wbufcid = 0;

		nsasync->nsasync_startc = CSTART;
		nsasync->nsasync_stopc = CSTOP;
		ns16550_program(ns16550, NS16550_INIT);
	} else
		if ((nsasync->nsasync_ttycommon.t_flags & TS_XCLUDE) &&
		    secpolicy_excl_open(cr) != 0) {
		mutex_exit(&ns16550->ns16550_excl_hi);
		mutex_exit(&ns16550->ns16550_excl);
		return (EBUSY);
	} else if ((*dev & OUTLINE) && !(nsasync->nsasync_flags & NSASYNC_OUT)) {
		mutex_exit(&ns16550->ns16550_excl_hi);
		mutex_exit(&ns16550->ns16550_excl);
		return (EBUSY);
	}

	if (*dev & OUTLINE)
		nsasync->nsasync_flags |= NSASYNC_OUT;

	/* Raise DTR on every open, but delay if it was just lowered. */
	while (nsasync->nsasync_flags & NSASYNC_DTR_DELAY) {
		DEBUGCONT1(NS16550_DEBUG_MODEM,
		    "ns16550%dopen: waiting for the NSASYNC_DTR_DELAY to be clear\n",
		    unit);
		mutex_exit(&ns16550->ns16550_excl_hi);
		if (cv_wait_sig(&nsasync->nsasync_flags_cv,
		    &ns16550->ns16550_excl) == 0) {
			DEBUGCONT1(NS16550_DEBUG_MODEM,
			    "ns16550%dopen: interrupted by signal, exiting\n",
			    unit);
			mutex_exit(&ns16550->ns16550_excl);
			return (EINTR);
		}
		mutex_enter(&ns16550->ns16550_excl_hi);
	}

	mcr = ns16550_get_mcr(ns16550);
	ns16550_set_mcr(ns16550,
	    mcr|(ns16550->ns16550_mcr&DTR));

	DEBUGCONT3(NS16550_DEBUG_INIT,
	    "ns16550%dopen: \"Raise DTR on every open\": make mcr = %x, "
	    "make TS_SOFTCAR = %s\n",
	    unit, mcr|(ns16550->ns16550_mcr&DTR),
	    (ns16550->ns16550_flags & NS16550_IGNORE_CD) ? "ON" : "OFF");

	if (ns16550->ns16550_flags & NS16550_IGNORE_CD) {
		DEBUGCONT1(NS16550_DEBUG_MODEM,
		    "ns16550%dopen: NS16550_IGNORE_CD set, set TS_SOFTCAR\n",
		    unit);
		nsasync->nsasync_ttycommon.t_flags |= TS_SOFTCAR;
	}
	else
		nsasync->nsasync_ttycommon.t_flags &= ~TS_SOFTCAR;

	/*
	 * Check carrier.
	 */
	ns16550->ns16550_msr = ns16550_get_msr(ns16550);
	DEBUGCONT3(NS16550_DEBUG_INIT, "ns16550%dopen: TS_SOFTCAR is %s, "
	    "MSR & DCD is %s\n",
	    unit,
	    (nsasync->nsasync_ttycommon.t_flags & TS_SOFTCAR) ? "set" : "clear",
	    (ns16550->ns16550_msr & DCD) ? "set" : "clear");

	if (ns16550->ns16550_msr & DCD)
		nsasync->nsasync_flags |= NSASYNC_CARR_ON;
	else
		nsasync->nsasync_flags &= ~NSASYNC_CARR_ON;
	mutex_exit(&ns16550->ns16550_excl_hi);

	/*
	 * If FNDELAY and FNONBLOCK are clear, block until carrier up.
	 * Quit on interrupt.
	 */
	if (!(flag & (FNDELAY|FNONBLOCK)) &&
	    !(nsasync->nsasync_ttycommon.t_cflag & CLOCAL)) {
		if ((!(nsasync->nsasync_flags & (NSASYNC_CARR_ON|NSASYNC_OUT)) &&
		    !(nsasync->nsasync_ttycommon.t_flags & TS_SOFTCAR)) ||
		    ((nsasync->nsasync_flags & NSASYNC_OUT) &&
		    !(*dev & OUTLINE))) {
			nsasync->nsasync_flags |= NSASYNC_WOPEN;
			if (cv_wait_sig(&nsasync->nsasync_flags_cv,
			    &ns16550->ns16550_excl) == B_FALSE) {
				nsasync->nsasync_flags &= ~NSASYNC_WOPEN;
				mutex_exit(&ns16550->ns16550_excl);
				return (EINTR);
			}
			nsasync->nsasync_flags &= ~NSASYNC_WOPEN;
			goto again;
		}
	} else if ((nsasync->nsasync_flags & NSASYNC_OUT) && !(*dev & OUTLINE)) {
		mutex_exit(&ns16550->ns16550_excl);
		return (EBUSY);
	}

	nsasync->nsasync_ttycommon.t_readq = rq;
	nsasync->nsasync_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)nsasync;
	mutex_exit(&ns16550->ns16550_excl);
	/*
	 * Caution here -- qprocson sets the pointers that are used by canput
	 * called by nsasync_softint.  NSASYNC_ISOPEN must *not* be set until those
	 * pointers are valid.
	 */
	qprocson(rq);
	nsasync->nsasync_flags |= NSASYNC_ISOPEN;
	nsasync->nsasync_polltid = 0;
	DEBUGCONT1(NS16550_DEBUG_INIT, "ns16550%dopen: done\n", unit);
	return (0);
}

static void
nsasync_progress_check(void *arg)
{
	struct nsasyncline *nsasync = arg;
	struct ns16550com	 *ns16550 = nsasync->nsasync_common;
	mblk_t *bp;

	/*
	 * We define "progress" as either waiting on a timed break or delay, or
	 * having had at least one transmitter interrupt.  If none of these are
	 * true, then just terminate the output and wake up that close thread.
	 */
	mutex_enter(&ns16550->ns16550_excl);
	mutex_enter(&ns16550->ns16550_excl_hi);
	if (!(nsasync->nsasync_flags & (NSASYNC_BREAK|NSASYNC_DELAY|NSASYNC_PROGRESS))) {
		nsasync->nsasync_ocnt = 0;
		nsasync->nsasync_flags &= ~NSASYNC_BUSY;
		nsasync->nsasync_timer = 0;
		bp = nsasync->nsasync_xmitblk;
		nsasync->nsasync_xmitblk = NULL;
		mutex_exit(&ns16550->ns16550_excl_hi);
		if (bp != NULL)
			freeb(bp);
		/*
		 * Since this timer is running, we know that we're in exit(2).
		 * That means that the user can't possibly be waiting on any
		 * valid ioctl(2) completion anymore, and we should just flush
		 * everything.
		 */
		flushq(nsasync->nsasync_ttycommon.t_writeq, FLUSHALL);
		cv_broadcast(&nsasync->nsasync_flags_cv);
	} else {
		nsasync->nsasync_flags &= ~NSASYNC_PROGRESS;
		nsasync->nsasync_timer = timeout(nsasync_progress_check, nsasync,
		    drv_usectohz(ns16550_drain_check));
		mutex_exit(&ns16550->ns16550_excl_hi);
	}
	mutex_exit(&ns16550->ns16550_excl);
}

/*
 * Release DTR so that ns16550open() can raise it.
 */
static void
nsasync_dtr_free(struct nsasyncline *nsasync)
{
	struct ns16550com *ns16550 = nsasync->nsasync_common;

	DEBUGCONT0(NS16550_DEBUG_MODEM,
	    "nsasync_dtr_free, clearing NSASYNC_DTR_DELAY\n");
	mutex_enter(&ns16550->ns16550_excl);
	nsasync->nsasync_flags &= ~NSASYNC_DTR_DELAY;
	nsasync->nsasync_dtrtid = 0;
	cv_broadcast(&nsasync->nsasync_flags_cv);
	mutex_exit(&ns16550->ns16550_excl);
}

/*
 * Close routine.
 */
/*ARGSUSED2*/
static int
ns16550close(queue_t *q, int flag, cred_t *credp)
{
	struct nsasyncline *nsasync;
	struct ns16550com	 *ns16550;
	int icr, lcr;
#ifdef DEBUG
	int instance;
#endif

	nsasync = (struct nsasyncline *)q->q_ptr;
	ASSERT(nsasync != NULL);
#ifdef DEBUG
	instance = UNIT(nsasync->nsasync_dev);
	DEBUGCONT1(NS16550_DEBUG_CLOSE, "ns16550%dclose\n", instance);
#endif
	ns16550 = nsasync->nsasync_common;

	mutex_enter(&ns16550->ns16550_excl);
	nsasync->nsasync_flags |= NSASYNC_CLOSING;

	/*
	 * Turn off PPS handling early to avoid events occuring during
	 * close.  Also reset the DCD edge monitoring bit.
	 */
	mutex_enter(&ns16550->ns16550_excl_hi);
	ns16550->ns16550_flags &= ~(NS16550_PPS | NS16550_PPS_EDGE);
	mutex_exit(&ns16550->ns16550_excl_hi);

	/*
	 * There are two flavors of break -- timed (M_BREAK or TCSBRK) and
	 * untimed (TIOCSBRK).  For the timed case, these are enqueued on our
	 * write queue and there's a timer running, so we don't have to worry
	 * about them.  For the untimed case, though, the user obviously made a
	 * mistake, because these are handled immediately.  We'll terminate the
	 * break now and honor his implicit request by discarding the rest of
	 * the data.
	 */
	if (nsasync->nsasync_flags & NSASYNC_OUT_SUSPEND) {
		if (nsasync->nsasync_utbrktid != 0) {
			(void) untimeout(nsasync->nsasync_utbrktid);
			nsasync->nsasync_utbrktid = 0;
		}
		mutex_enter(&ns16550->ns16550_excl_hi);
		ns16550_set_break(ns16550, B_FALSE);
		mutex_exit(&ns16550->ns16550_excl_hi);
		nsasync->nsasync_flags &= ~NSASYNC_OUT_SUSPEND;
		goto nodrain;
	}

	/*
	 * If the user told us not to delay the close ("non-blocking"), then
	 * don't bother trying to drain.
	 *
	 * If the user did M_STOP (NSASYNC_STOPPED), there's no hope of ever
	 * getting an M_START (since these messages aren't enqueued), and the
	 * only other way to clear the stop condition is by loss of DCD, which
	 * would discard the queue data.  Thus, we drop the output data if
	 * NSASYNC_STOPPED is set.
	 */
	if ((flag & (FNDELAY|FNONBLOCK)) ||
	    (nsasync->nsasync_flags & NSASYNC_STOPPED)) {
		goto nodrain;
	}

	/*
	 * If there's any pending output, then we have to try to drain it.
	 * There are two main cases to be handled:
	 *	- called by close(2): need to drain until done or until
	 *	  a signal is received.  No timeout.
	 *	- called by exit(2): need to drain while making progress
	 *	  or until a timeout occurs.  No signals.
	 *
	 * If we can't rely on receiving a signal to get us out of a hung
	 * session, then we have to use a timer.  In this case, we set a timer
	 * to check for progress in sending the output data -- all that we ask
	 * (at each interval) is that there's been some progress made.  Since
	 * the interrupt routine grabs buffers from the write queue, we can't
	 * trust changes in nsasync_ocnt.  Instead, we use a progress flag.
	 *
	 * Note that loss of carrier will cause the output queue to be flushed,
	 * and we'll wake up again and finish normally.
	 */
	if (!ddi_can_receive_sig() && ns16550_drain_check != 0) {
		nsasync->nsasync_flags &= ~NSASYNC_PROGRESS;
		nsasync->nsasync_timer = timeout(nsasync_progress_check, nsasync,
		    drv_usectohz(ns16550_drain_check));
	}
	while (nsasync->nsasync_ocnt > 0 ||
	    nsasync->nsasync_ttycommon.t_writeq->q_first != NULL ||
	    (nsasync->nsasync_flags & (NSASYNC_BUSY|NSASYNC_BREAK|NSASYNC_DELAY))) {
		if (cv_wait_sig(&nsasync->nsasync_flags_cv, &ns16550->ns16550_excl) == 0)
			break;
	}
	if (nsasync->nsasync_timer != 0) {
		(void) untimeout(nsasync->nsasync_timer);
		nsasync->nsasync_timer = 0;
	}

nodrain:
	nsasync->nsasync_ocnt = 0;
	if (nsasync->nsasync_xmitblk != NULL)
		freeb(nsasync->nsasync_xmitblk);
	nsasync->nsasync_xmitblk = NULL;

	/*
	 * If line has HUPCL set or is incompletely opened fix up the modem
	 * lines.
	 */
	DEBUGCONT1(NS16550_DEBUG_MODEM, "ns16550%dclose: next check HUPCL flag\n",
	    instance);
	mutex_enter(&ns16550->ns16550_excl_hi);
	if ((nsasync->nsasync_ttycommon.t_cflag & HUPCL) ||
	    (nsasync->nsasync_flags & NSASYNC_WOPEN)) {
		DEBUGCONT3(NS16550_DEBUG_MODEM,
		    "ns16550%dclose: HUPCL flag = %x, NSASYNC_WOPEN flag = %x\n",
		    instance,
		    nsasync->nsasync_ttycommon.t_cflag & HUPCL,
		    nsasync->nsasync_ttycommon.t_cflag & NSASYNC_WOPEN);
		nsasync->nsasync_flags |= NSASYNC_DTR_DELAY;

		/* turn off DTR, RTS but NOT interrupt to 386 */
		if (ns16550->ns16550_flags & (NS16550_IGNORE_CD|NS16550_RTS_DTR_OFF)) {
			DEBUGCONT3(NS16550_DEBUG_MODEM,
			    "ns16550%dclose: NS16550_IGNORE_CD flag = %x, "
			    "NS16550_RTS_DTR_OFF flag = %x\n",
			    instance,
			    ns16550->ns16550_flags & NS16550_IGNORE_CD,
			    ns16550->ns16550_flags & NS16550_RTS_DTR_OFF);

			ns16550_set_mcr(ns16550, ns16550->ns16550_mcr|OUT2);
		} else {
			DEBUGCONT1(NS16550_DEBUG_MODEM,
			    "ns16550%dclose: Dropping DTR and RTS\n", instance);
			ns16550_set_mcr(ns16550, ns16550->ns16550_mcr|OUT2);
		}
		nsasync->nsasync_dtrtid =
		    timeout((void (*)())nsasync_dtr_free,
		    (caddr_t)nsasync, drv_usectohz(ns16550_min_dtr_low));
	}
	/*
	 * If nobody's using it now, turn off receiver interrupts.
	 */
	if ((nsasync->nsasync_flags & (NSASYNC_WOPEN|NSASYNC_ISOPEN)) == 0) {
		ns16550_set_icr(ns16550, 0, RIEN);
	}
	mutex_exit(&ns16550->ns16550_excl_hi);
out:
	ttycommon_close(&nsasync->nsasync_ttycommon);

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (nsasync->nsasync_wbufcid != 0) {
		unbufcall(nsasync->nsasync_wbufcid);
		nsasync->nsasync_wbufcid = 0;
	}

	/* Note that qprocsoff can't be done until after interrupts are off */
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	nsasync->nsasync_ttycommon.t_readq = NULL;
	nsasync->nsasync_ttycommon.t_writeq = NULL;

	/*
	 * Clear out device state, except persistant device property flags.
	 */
	nsasync->nsasync_flags &= (NSASYNC_DTR_DELAY|NS16550_RTS_DTR_OFF);
	cv_broadcast(&nsasync->nsasync_flags_cv);
	mutex_exit(&ns16550->ns16550_excl);

	DEBUGCONT1(NS16550_DEBUG_CLOSE, "ns16550%dclose: done\n", instance);
	return (0);
}

static boolean_t
ns16550_isbusy(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync;

	DEBUGCONT0(NS16550_DEBUG_EOT, "ns16550_isbusy\n");
	nsasync = ns16550->ns16550_priv;
	ASSERT(mutex_owned(&ns16550->ns16550_excl));
	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));
/*
 * XXXX this should be recoded
 */
	return ((nsasync->nsasync_ocnt > 0) || ns16550_is_busy(ns16550));
}

static void
ns16550_waiteot(struct ns16550com *ns16550)
{
	/*
	 * Wait for the current transmission block and the
	 * current fifo data to transmit. Once this is done
	 * we may go on.
	 */
	DEBUGCONT0(NS16550_DEBUG_EOT, "ns16550_waiteot\n");
	ASSERT(mutex_owned(&ns16550->ns16550_excl));
	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));
	while (ns16550_isbusy(ns16550)) {
		mutex_exit(&ns16550->ns16550_excl_hi);
		mutex_exit(&ns16550->ns16550_excl);
		drv_usecwait(10000);		/* wait .01 */
		mutex_enter(&ns16550->ns16550_excl);
		mutex_enter(&ns16550->ns16550_excl_hi);
	}
}

/*
 * Program the NS16550 port. Most of the nsasync operation is based on the values
 * of 'c_iflag' and 'c_cflag'.
 */

#define	BAUDINDEX(cflg)	(((cflg) & CBAUDEXT) ? \
			(((cflg) & CBAUD) + CBAUD + 1) : ((cflg) & CBAUD))

static void
ns16550_program(struct ns16550com *ns16550, int mode)
{
	struct nsasyncline *nsasync;
	int baudrate, c_flag;
	int icr, lcr;
	int flush_reg;
	int ocflags;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&ns16550->ns16550_excl));
	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));

	nsasync = ns16550->ns16550_priv;
#ifdef DEBUG
	instance = UNIT(nsasync->nsasync_dev);
	DEBUGCONT2(NS16550_DEBUG_PROCS,
	    "ns16550%d_program: mode = 0x%08X, enter\n", instance, mode);
#endif

	baudrate = BAUDINDEX(nsasync->nsasync_ttycommon.t_cflag);

	nsasync->nsasync_ttycommon.t_cflag &= ~(CIBAUD);

	if (baudrate > CBAUD) {
		nsasync->nsasync_ttycommon.t_cflag |= CIBAUDEXT;
		nsasync->nsasync_ttycommon.t_cflag |=
		    (((baudrate - CBAUD - 1) << IBSHIFT) & CIBAUD);
	} else {
		nsasync->nsasync_ttycommon.t_cflag &= ~CIBAUDEXT;
		nsasync->nsasync_ttycommon.t_cflag |=
		    ((baudrate << IBSHIFT) & CIBAUD);
	}

	c_flag = nsasync->nsasync_ttycommon.t_cflag &
	    (CLOCAL|CREAD|CSTOPB|CSIZE|PARENB|PARODD|CBAUD|CBAUDEXT);

	ocflags = ns16550->ns16550_ocflag;

	ns16550_reset(ns16550);
	ns16550->ns16550_msr = ns16550_get_msr(ns16550);
	/*
	 * The device is programmed in the open sequence, if we
	 * have to hardware handshake, then this is a good time
	 * to check if the device can receive any data.
	 */

	if ((CRTSCTS & nsasync->nsasync_ttycommon.t_cflag) && !(ns16550->ns16550_msr & CTS)) {
		nsasync_flowcontrol_hw_output(ns16550, FLOW_STOP);
	} else {
		/*
		 * We can not use nsasync_flowcontrol_hw_output(ns16550, FLOW_START)
		 * here, because if CRTSCTS is clear, we need clear
		 * NSASYNC_HW_OUT_FLW bit.
		 */
		nsasync->nsasync_flags &= ~NSASYNC_HW_OUT_FLW;
	}

	/*
	 * If IXON is not set, clear NSASYNC_SW_OUT_FLW;
	 * If IXON is set, no matter what IXON flag is before this
	 * function call to ns16550_program,
	 * we will use the old NSASYNC_SW_OUT_FLW status.
	 * Because of handling IXON in the driver, we also should re-calculate
	 * the value of NSASYNC_OUT_FLW_RESUME bit, but in fact,
	 * the TCSET* commands which call ns16550_program
	 * are put into the write queue, so there is no output needed to
	 * be resumed at this point.
	 */
	if (!(IXON & nsasync->nsasync_ttycommon.t_iflag))
		nsasync->nsasync_flags &= ~NSASYNC_SW_OUT_FLW;

	if (mode == NS16550_INIT)
		while (ns16550_rx_is_ready(ns16550))
			ns16550_get_char(ns16550);

	if (ocflags != (c_flag & ~CLOCAL) || mode == NS16550_INIT) {
		/* Set line control */
		lcr = ns16550_get_lcr(ns16550);
		lcr &= ~(WLS0|WLS1|STB|PEN|EPS);

		if (c_flag & CSTOPB)
			lcr |= STB;	/* 2 stop bits */

		if (c_flag & PARENB)
			lcr |= PEN;

		if ((c_flag & PARODD) == 0)
			lcr |= EPS;

		switch (c_flag & CSIZE) {
		case CS5:
			lcr |= BITS5;
			break;
		case CS6:
			lcr |= BITS6;
			break;
		case CS7:
			lcr |= BITS7;
			break;
		case CS8:
			lcr |= BITS8;
			break;
		}

		/* set the baud rate, unless it is "0" */
		if (baudrate != 0)
			ns16550_set_baud(ns16550, baudrate);

		/* set the line control modes */
		ns16550_set_lcr(ns16550, lcr);

		/*
		 * If we have a FIFO buffer, enable/flush
		 * at intialize time, flush if transitioning from
		 * CREAD off to CREAD on.
		 */
		if ((ocflags & CREAD) == 0 && (c_flag & CREAD) ||
		    mode == NS16550_INIT)
			ns16550_reset_fifo(ns16550, FIFORXFLSH);

		/* remember the new cflags */
		ns16550->ns16550_ocflag = c_flag & ~CLOCAL;
	}

	if (baudrate == 0)
		ns16550_set_mcr(ns16550,
		    (ns16550->ns16550_mcr & RTS) | OUT2);
	else
		ns16550_set_mcr(ns16550,
		    ns16550->ns16550_mcr | OUT2);

	/*
	 * Call the modem status interrupt handler to check for the carrier
	 * in case CLOCAL was turned off after the carrier came on.
	 * (Note: Modem status interrupt is not enabled if CLOCAL is ON.)
	 */
	nsasync_msint(ns16550);

	/* Set interrupt control */
	DEBUGCONT3(NS16550_DEBUG_MODM2,
	    "ns16550%d_program: c_flag & CLOCAL = %x t_cflag & CRTSCTS = %x\n",
	    instance, c_flag & CLOCAL,
	    nsasync->nsasync_ttycommon.t_cflag & CRTSCTS);

	if ((c_flag & CLOCAL) && !(nsasync->nsasync_ttycommon.t_cflag & CRTSCTS))
		/*
		 * direct-wired line ignores DCD, so we don't enable modem
		 * status interrupts.
		 */
		icr = (TIEN | SIEN);
	else
		icr = (TIEN | SIEN | MIEN);

	if (c_flag & CREAD)
		icr |= RIEN;

	ns16550_set_icr(ns16550, icr, 0xff);
	DEBUGCONT1(NS16550_DEBUG_PROCS, "ns16550%d_program: done\n", instance);
}

static boolean_t
ns16550_baudok(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int baudrate;

	baudrate = BAUDINDEX(nsasync->nsasync_ttycommon.t_cflag);

	return (baudrate >= N_SU_SPEEDS)? B_FALSE: B_TRUE;
}

/*
 * ns16550intr() is the High Level Interrupt Handler.
 *
 * There are four different interrupt types indexed by ISR register values:
 *		0: modem
 *		1: Tx holding register is empty, ready for next char
 *		2: Rx register now holds a char to be picked up
 *		3: error or break on line
 * This routine checks the Bit 0 (interrupt-not-pending) to determine if
 * the interrupt is from this port.
 */
uint_t
ns16550intr(caddr_t argns16550)
{
	struct ns16550com		*ns16550 = (struct ns16550com *)argns16550;
	struct nsasyncline	*nsasync;
	int			ret_status = DDI_INTR_UNCLAIMED;
	uchar_t			interrupt_id, lsr;

	interrupt_id = ns16550_get_isr(ns16550);
	nsasync = ns16550->ns16550_priv;
	if ((nsasync == NULL) ||
	    !(nsasync->nsasync_flags & (NSASYNC_ISOPEN|NSASYNC_WOPEN))) {
		if (interrupt_id & NOINTERRUPT)
			return (DDI_INTR_UNCLAIMED);
		else {
			/*
			 * reset the device by:
			 *	reading line status
			 *	reading any data from data status register
			 *	reading modem status
			 */
			(void) ns16550_get_lsr(ns16550);
			(void) ns16550_get_char(ns16550);
			ns16550->ns16550_msr = ns16550_get_msr(ns16550);
			return (DDI_INTR_CLAIMED);
		}
	}

	mutex_enter(&ns16550->ns16550_excl_hi);

	if (ns16550->ns16550_flags & NS16550_DDI_SUSPENDED) {
		mutex_exit(&ns16550->ns16550_excl_hi);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We will loop until the interrupt line is pulled low. ns16550
	 * interrupt is edge triggered.
	 */
	/* CSTYLED */
	for (;; interrupt_id =
	    ns16550_get_isr(ns16550)) {

		if (interrupt_id & NOINTERRUPT)
			break;
		ret_status = DDI_INTR_CLAIMED;

		DEBUGCONT1(NS16550_DEBUG_INTR, "ns16550intr: interrupt_id = 0x%d\n",
		    interrupt_id);
		lsr = ns16550_get_lsr(ns16550);
		switch (interrupt_id) {
		case RxRDY:
		case RSTATUS:
		case FFTMOUT:
			/* receiver interrupt or receiver errors */
			nsasync_rxint(ns16550, lsr);
			break;
		case TxRDY:
			/* transmit interrupt */
			nsasync_txint(ns16550);
			continue;
		case MSTATUS:
			/* modem status interrupt */
			nsasync_msint(ns16550);
			break;
		}
		if ((lsr & XHRE) && (nsasync->nsasync_flags & NSASYNC_BUSY) &&
		    (nsasync->nsasync_ocnt > 0))
			nsasync_txint(ns16550);
	}
	mutex_exit(&ns16550->ns16550_excl_hi);
	return (ret_status);
}

/*
 * Transmitter interrupt service routine.
 * If there is more data to transmit in the current pseudo-DMA block,
 * send the next character if output is not stopped or draining.
 * Otherwise, queue up a soft interrupt.
 *
 * XXX -  Needs review for HW FIFOs.
 */
static void
nsasync_txint(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;

	ASSERT(MUTEX_HELD(&ns16550->ns16550_excl_hi));

	/*
	 * If NSASYNC_BREAK or NSASYNC_OUT_SUSPEND has been set, return to
	 * ns16550intr()'s context to claim the interrupt without performing
	 * any action. No character will be loaded into FIFO/THR until
	 * timed or untimed break is removed
	 */
	if (nsasync->nsasync_flags & (NSASYNC_BREAK|NSASYNC_OUT_SUSPEND))
		return;

	nsasync_flowcontrol_sw_input(ns16550, FLOW_CHECK, IN_FLOW_NULL);

	if (!(nsasync->nsasync_flags &
	    (NSASYNC_HW_OUT_FLW|NSASYNC_SW_OUT_FLW|NSASYNC_STOPPED))) {
		while (nsasync->nsasync_ocnt > 0) {
			if (!ns16550_tx_is_ready(ns16550)) {
				break;
			}
			ns16550_put_char(ns16550, *nsasync->nsasync_optr++);
			nsasync->nsasync_ocnt--;
		}
		nsasync->nsasync_flags |= NSASYNC_PROGRESS;
	}

	NS16550SETSOFT(ns16550);
}

/*
 * Interrupt on port: handle PPS event.  This function is only called
 * for a port on which PPS event handling has been enabled.
 */
static void
ns16550_ppsevent(struct ns16550com *ns16550, int msr)
{
	ASSERT(MUTEX_HELD(&ns16550->ns16550_excl_hi));

	if (ns16550->ns16550_flags & NS16550_PPS_EDGE) {
		/* Have seen leading edge, now look for and record drop */
		if ((msr & DCD) == 0)
			ns16550->ns16550_flags &= ~NS16550_PPS_EDGE;
		/*
		 * Waiting for leading edge, look for rise; stamp event and
		 * calibrate kernel clock.
		 */
	} else if (msr & DCD) {
			/*
			 * This code captures a timestamp at the designated
			 * transition of the PPS signal (DCD asserted).  The
			 * code provides a pointer to the timestamp, as well
			 * as the hardware counter value at the capture.
			 *
			 * Note: the kernel has nano based time values while
			 * NTP requires micro based, an in-line fast algorithm
			 * to convert nsec to usec is used here -- see hrt2ts()
			 * in common/os/timers.c for a full description.
			 */
			struct timeval *tvp = &ns16550_ppsev.tv;
			timestruc_t ts;
			long nsec, usec;

			ns16550->ns16550_flags |= NS16550_PPS_EDGE;
			LED_OFF;
			gethrestime(&ts);
			LED_ON;
			nsec = ts.tv_nsec;
			usec = nsec + (nsec >> 2);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 4);
			usec = nsec - (usec >> 3);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 3);
			usec = nsec + (usec >> 4);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 6);
			tvp->tv_usec = usec >> 10;
			tvp->tv_sec = ts.tv_sec;

			++ns16550_ppsev.serial;

			/*
			 * Because the kernel keeps a high-resolution time,
			 * pass the current highres timestamp in tvp and zero
			 * in usec.
			 */
			ddi_hardpps(tvp, 0);
	}
}

/*
 * Receiver interrupt: RxRDY interrupt, FIFO timeout interrupt or receive
 * error interrupt.
 * Try to put the character into the circular buffer for this line; if it
 * overflows, indicate a circular buffer overrun. If this port is always
 * to be serviced immediately, or the character is a STOP character, or
 * more than 15 characters have arrived, queue up a soft interrupt to
 * drain the circular buffer.
 * XXX - needs review for hw FIFOs support.
 */

static void
nsasync_rxint(struct ns16550com *ns16550, uchar_t lsr)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	uchar_t c;
	uint_t s, needsoft = 0;
	tty_common_t *tp;

	ASSERT(MUTEX_HELD(&ns16550->ns16550_excl_hi));

	tp = &nsasync->nsasync_ttycommon;
	if (!(tp->t_cflag & CREAD)) {
		while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
			(void) ns16550_get_char(ns16550);
			lsr = ns16550_get_lsr(ns16550);
		}
		return; /* line is not open for read? */
	}

	while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
		c = 0;
		s = 0;				/* reset error status */
		if (lsr & RCA) {
			c = ns16550_get_char(ns16550);

			/*
			 * We handle XON/XOFF char if IXON is set,
			 * but if received char is _POSIX_VDISABLE,
			 * we left it to the up level module.
			 */
			if (tp->t_iflag & IXON) {
				if ((c == nsasync->nsasync_stopc) &&
				    (c != _POSIX_VDISABLE)) {
					nsasync_flowcontrol_sw_output(ns16550,
					    FLOW_STOP);
					goto check_looplim;
				} else if ((c == nsasync->nsasync_startc) &&
				    (c != _POSIX_VDISABLE)) {
					nsasync_flowcontrol_sw_output(ns16550,
					    FLOW_START);
					needsoft = 1;
					goto check_looplim;
				}
				if ((tp->t_iflag & IXANY) &&
				    (nsasync->nsasync_flags & NSASYNC_SW_OUT_FLW)) {
					nsasync_flowcontrol_sw_output(ns16550,
					    FLOW_START);
					needsoft = 1;
				}
			}
		}

		/*
		 * Check for character break sequence
		 */
		if ((abort_enable == KIOCABORTALTERNATE) &&
		    (ns16550->ns16550_flags & NS16550_CONSOLE)) {
			if (abort_charseq_recognize(c))
				abort_sequence_enter((char *)NULL);
		}

		/* Handle framing errors */
		if (lsr & (PARERR|FRMERR|BRKDET|OVRRUN)) {
			if (lsr & PARERR) {
				if (tp->t_iflag & INPCK) /* parity enabled */
					s |= PERROR;
			}

			if (lsr & (FRMERR|BRKDET))
				s |= FRERROR;
			if (lsr & OVRRUN) {
				nsasync->nsasync_hw_overrun = 1;
				s |= OVERRUN;
			}
		}

		if (s == 0)
			if ((tp->t_iflag & PARMRK) &&
			    !(tp->t_iflag & (IGNPAR|ISTRIP)) &&
			    (c == 0377))
				if (RING_POK(nsasync, 2)) {
					RING_PUT(nsasync, 0377);
					RING_PUT(nsasync, c);
				} else
					nsasync->nsasync_sw_overrun = 1;
			else
				if (RING_POK(nsasync, 1))
					RING_PUT(nsasync, c);
				else
					nsasync->nsasync_sw_overrun = 1;
		else
			if (s & FRERROR) /* Handle framing errors */
				if (c == 0)
					if ((ns16550->ns16550_flags & NS16550_CONSOLE) &&
					    (abort_enable !=
					    KIOCABORTALTERNATE))
						abort_sequence_enter((char *)0);
					else
						nsasync->nsasync_break++;
				else
					if (RING_POK(nsasync, 1))
						RING_MARK(nsasync, c, s);
					else
						nsasync->nsasync_sw_overrun = 1;
			else /* Parity errors are handled by ldterm */
				if (RING_POK(nsasync, 1))
					RING_MARK(nsasync, c, s);
				else
					nsasync->nsasync_sw_overrun = 1;
check_looplim:
		lsr = ns16550_get_lsr(ns16550);
	}
	if ((RING_CNT(nsasync) > (RINGSIZE * 3)/4) &&
	    !(nsasync->nsasync_inflow_source & IN_FLOW_RINGBUFF)) {
		nsasync_flowcontrol_hw_input(ns16550, FLOW_STOP, IN_FLOW_RINGBUFF);
		(void) nsasync_flowcontrol_sw_input(ns16550, FLOW_STOP,
		    IN_FLOW_RINGBUFF);
	}

	if ((nsasync->nsasync_flags & NSASYNC_SERVICEIMM) || needsoft ||
	    (RING_FRAC(nsasync)) || (nsasync->nsasync_polltid == 0)) {
		NS16550SETSOFT(ns16550);	/* need a soft interrupt */
	}
}

/*
 * Modem status interrupt.
 *
 * (Note: It is assumed that the MSR hasn't been read by ns16550intr().)
 */

static void
nsasync_msint(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int msr, t_cflag = nsasync->nsasync_ttycommon.t_cflag;
#ifdef DEBUG
	int instance = UNIT(nsasync->nsasync_dev);
#endif

	ASSERT(MUTEX_HELD(&ns16550->ns16550_excl_hi));

nsasync_msint_retry:
	/* this resets the interrupt */
	msr = ns16550_get_msr(ns16550);
	DEBUGCONT10(NS16550_DEBUG_STATE,
	    "ns16550nc%d_msint call #%d:\n"
	    "   transition: %3s %3s %3s %3s\n"
	    "current state: %3s %3s %3s %3s\n",
	    instance,
	    ++(ns16550->ns16550_msint_cnt),
	    (msr & DCTS) ? "DCTS" : "    ",
	    (msr & DDSR) ? "DDSR" : "    ",
	    (msr & DRI)  ? "DRI " : "    ",
	    (msr & DDCD) ? "DDCD" : "    ",
	    (msr & CTS)  ? "CTS " : "    ",
	    (msr & DSR)  ? "DSR " : "    ",
	    (msr & RI)   ? "RI  " : "    ",
	    (msr & DCD)  ? "DCD " : "    ");

	/* If CTS status is changed, do H/W output flow control */
	if ((t_cflag & CRTSCTS) && (((ns16550->ns16550_msr ^ msr) & CTS) != 0))
		nsasync_flowcontrol_hw_output(ns16550,
		    msr & CTS ? FLOW_START : FLOW_STOP);
	/*
	 * Reading MSR resets the interrupt, we save the
	 * value of msr so that other functions could examine MSR by
	 * looking at ns16550_msr.
	 */
	ns16550->ns16550_msr = (uchar_t)msr;

	/* Handle PPS event */
	if (ns16550->ns16550_flags & NS16550_PPS)
		ns16550_ppsevent(ns16550, msr);

	nsasync->nsasync_ext++;
	NS16550SETSOFT(ns16550);
	/*
	 * We will make sure that the modem status presented to us
	 * during the previous read has not changed. If the chip samples
	 * the modem status on the falling edge of the interrupt line,
	 * and uses this state as the base for detecting change of modem
	 * status, we would miss a change of modem status event that occured
	 * after we initiated a read MSR operation.
	 */
	msr = ns16550_get_msr(ns16550);
	if (STATES(msr) != STATES(ns16550->ns16550_msr))
		goto	nsasync_msint_retry;
}

/*
 * Handle a second-stage interrupt.
 */
/*ARGSUSED*/
uint_t
ns16550softintr(caddr_t intarg)
{
	struct ns16550com *ns16550 = (struct ns16550com *)intarg;
	struct nsasyncline *nsasync;
	int rv;
	uint_t cc;

	/*
	 * Test and clear soft interrupt.
	 */
	mutex_enter(&ns16550->ns16550_soft_lock);
	DEBUGCONT0(NS16550_DEBUG_PROCS, "ns16550softintr: enter\n");
	rv = ns16550->ns16550softpend;
	if (rv != 0)
		ns16550->ns16550softpend = 0;
	mutex_exit(&ns16550->ns16550_soft_lock);

	if (rv) {
		if (ns16550->ns16550_priv == NULL)
			return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
		nsasync = (struct nsasyncline *)ns16550->ns16550_priv;
		mutex_enter(&ns16550->ns16550_excl_hi);
		if (ns16550->ns16550_flags & NS16550_NEEDSOFT) {
			ns16550->ns16550_flags &= ~NS16550_NEEDSOFT;
			mutex_exit(&ns16550->ns16550_excl_hi);
			nsasync_softint(ns16550);
			mutex_enter(&ns16550->ns16550_excl_hi);
		}

		/*
		 * There are some instances where the softintr is not
		 * scheduled and hence not called. It so happens that
		 * causes the last few characters to be stuck in the
		 * ringbuffer. Hence, call the handler once again so
		 * the last few characters are cleared.
		 */
		cc = RING_CNT(nsasync);
		mutex_exit(&ns16550->ns16550_excl_hi);
		if (cc > 0)
			(void) nsasync_softint(ns16550);
	}
	return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * Handle a software interrupt.
 */
static void
nsasync_softint(struct ns16550com *ns16550)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	uint_t	cc;
	mblk_t	*bp;
	queue_t	*q;
	uchar_t	val;
	uchar_t	c;
	tty_common_t	*tp;
	int nb;
	int instance = UNIT(nsasync->nsasync_dev);

	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_softint\n", instance);
	mutex_enter(&ns16550->ns16550_excl_hi);
	if (ns16550->ns16550_flags & NS16550_DOINGSOFT) {
		ns16550->ns16550_flags |= NS16550_DOINGSOFT_RETRY;
		mutex_exit(&ns16550->ns16550_excl_hi);
		return;
	}
	ns16550->ns16550_flags |= NS16550_DOINGSOFT;
begin:
	ns16550->ns16550_flags &= ~NS16550_DOINGSOFT_RETRY;
	mutex_exit(&ns16550->ns16550_excl_hi);
	mutex_enter(&ns16550->ns16550_excl);
	tp = &nsasync->nsasync_ttycommon;
	q = tp->t_readq;
	if (nsasync->nsasync_flags & NSASYNC_OUT_FLW_RESUME) {
		if (nsasync->nsasync_ocnt > 0) {
			mutex_enter(&ns16550->ns16550_excl_hi);
			nsasync_resume(nsasync);
			mutex_exit(&ns16550->ns16550_excl_hi);
		} else {
			if (nsasync->nsasync_xmitblk)
				freeb(nsasync->nsasync_xmitblk);
			nsasync->nsasync_xmitblk = NULL;
			nsasync_start(nsasync);
		}
		nsasync->nsasync_flags &= ~NSASYNC_OUT_FLW_RESUME;
	}
	mutex_enter(&ns16550->ns16550_excl_hi);
	if (nsasync->nsasync_ext) {
		nsasync->nsasync_ext = 0;
		/* check for carrier up */
		DEBUGCONT3(NS16550_DEBUG_MODM2,
		    "nsasync%d_softint: ns16550_msr & DCD = %x, "
		    "tp->t_flags & TS_SOFTCAR = %x\n",
		    instance, ns16550->ns16550_msr & DCD, tp->t_flags & TS_SOFTCAR);

		if (ns16550->ns16550_msr & DCD) {
			/* carrier present */
			if ((nsasync->nsasync_flags & NSASYNC_CARR_ON) == 0) {
				DEBUGCONT1(NS16550_DEBUG_MODM2,
				    "nsasync%d_softint: set NSASYNC_CARR_ON\n",
				    instance);
				nsasync->nsasync_flags |= NSASYNC_CARR_ON;
				if (nsasync->nsasync_flags & NSASYNC_ISOPEN) {
					mutex_exit(&ns16550->ns16550_excl_hi);
					mutex_exit(&ns16550->ns16550_excl);
					(void) putctl(q, M_UNHANGUP);
					mutex_enter(&ns16550->ns16550_excl);
					mutex_enter(&ns16550->ns16550_excl_hi);
				}
				cv_broadcast(&nsasync->nsasync_flags_cv);
			}
		} else {
			if ((nsasync->nsasync_flags & NSASYNC_CARR_ON) &&
			    !(tp->t_cflag & CLOCAL) &&
			    !(tp->t_flags & TS_SOFTCAR)) {
				int flushflag;

				DEBUGCONT1(NS16550_DEBUG_MODEM,
				    "nsasync%d_softint: carrier dropped, "
				    "so drop DTR\n",
				    instance);
				/*
				 * Carrier went away.
				 * Drop DTR, abort any output in
				 * progress, indicate that output is
				 * not stopped, and send a hangup
				 * notification upstream.
				 */
				val = ns16550_get_mcr(ns16550);
				ns16550_set_mcr(ns16550, (val & ~DTR));

				if (nsasync->nsasync_flags & NSASYNC_BUSY) {
					DEBUGCONT0(NS16550_DEBUG_BUSY,
					    "nsasync_softint: "
					    "Carrier dropped.  "
					    "Clearing nsasync_ocnt\n");
					nsasync->nsasync_ocnt = 0;
				}	/* if */

				nsasync->nsasync_flags &= ~NSASYNC_STOPPED;
				if (nsasync->nsasync_flags & NSASYNC_ISOPEN) {
					mutex_exit(&ns16550->ns16550_excl_hi);
					mutex_exit(&ns16550->ns16550_excl);
					(void) putctl(q, M_HANGUP);
					mutex_enter(&ns16550->ns16550_excl);
					DEBUGCONT1(NS16550_DEBUG_MODEM,
					    "nsasync%d_softint: "
					    "putctl(q, M_HANGUP)\n",
					    instance);
					/*
					 * Flush FIFO buffers
					 * Any data left in there is invalid now
					 */
					ns16550_reset_fifo(ns16550, FIFOTXFLSH);
					/*
					 * Flush our write queue if we have one.
					 * If we're in the midst of close, then
					 * flush everything. Don't leave stale
					 * ioctls lying about.
					 */
					flushflag = (nsasync->nsasync_flags &
					    NSASYNC_CLOSING) ? FLUSHALL :
					    FLUSHDATA;
					flushq(tp->t_writeq, flushflag);

					/* active msg */
					bp = nsasync->nsasync_xmitblk;
					if (bp != NULL) {
						freeb(bp);
						nsasync->nsasync_xmitblk = NULL;
					}

					mutex_enter(&ns16550->ns16550_excl_hi);
					nsasync->nsasync_flags &= ~NSASYNC_BUSY;
					/*
					 * This message warns of Carrier loss
					 * with data left to transmit can hang
					 * the system.
					 */
					DEBUGCONT0(NS16550_DEBUG_MODEM,
					    "nsasync_softint: Flushing to "
					    "prevent HUPCL hanging\n");
				}	/* if (NSASYNC_ISOPEN) */
			}	/* if (NSASYNC_CARR_ON && CLOCAL) */
			nsasync->nsasync_flags &= ~NSASYNC_CARR_ON;
			cv_broadcast(&nsasync->nsasync_flags_cv);
		}	/* else */
	}	/* if (nsasync->nsasync_ext) */

	mutex_exit(&ns16550->ns16550_excl_hi);

	/*
	 * If data has been added to the circular buffer, remove
	 * it from the buffer, and send it up the stream if there's
	 * somebody listening. Try to do it 16 bytes at a time. If we
	 * have more than 16 bytes to move, move 16 byte chunks and
	 * leave the rest for next time around (maybe it will grow).
	 */
	mutex_enter(&ns16550->ns16550_excl_hi);
	if (!(nsasync->nsasync_flags & NSASYNC_ISOPEN)) {
		RING_INIT(nsasync);
		goto rv;
	}
	if ((cc = RING_CNT(nsasync)) == 0)
		goto rv;
	mutex_exit(&ns16550->ns16550_excl_hi);

	if (!canput(q)) {
		mutex_enter(&ns16550->ns16550_excl_hi);
		if (!(nsasync->nsasync_inflow_source & IN_FLOW_STREAMS)) {
			nsasync_flowcontrol_hw_input(ns16550, FLOW_STOP,
			    IN_FLOW_STREAMS);
			(void) nsasync_flowcontrol_sw_input(ns16550, FLOW_STOP,
			    IN_FLOW_STREAMS);
		}
		goto rv;
	}
	if (nsasync->nsasync_inflow_source & IN_FLOW_STREAMS) {
		mutex_enter(&ns16550->ns16550_excl_hi);
		nsasync_flowcontrol_hw_input(ns16550, FLOW_START,
		    IN_FLOW_STREAMS);
		(void) nsasync_flowcontrol_sw_input(ns16550, FLOW_START,
		    IN_FLOW_STREAMS);
		mutex_exit(&ns16550->ns16550_excl_hi);
	}

	DEBUGCONT2(NS16550_DEBUG_INPUT, "nsasync%d_softint: %d char(s) in queue.\n",
	    instance, cc);

	if (!(bp = allocb(cc, BPRI_MED))) {
		mutex_exit(&ns16550->ns16550_excl);
		ttycommon_qfull(&nsasync->nsasync_ttycommon, q);
		mutex_enter(&ns16550->ns16550_excl);
		mutex_enter(&ns16550->ns16550_excl_hi);
		goto rv;
	}
	mutex_enter(&ns16550->ns16550_excl_hi);
	do {
		if (RING_ERR(nsasync, S_ERRORS)) {
			RING_UNMARK(nsasync);
			c = RING_GET(nsasync);
			break;
		} else
			*bp->b_wptr++ = RING_GET(nsasync);
	} while (--cc);
	mutex_exit(&ns16550->ns16550_excl_hi);
	mutex_exit(&ns16550->ns16550_excl);
	if (bp->b_wptr > bp->b_rptr) {
			if (!canput(q)) {
				ns16550error(CE_NOTE, "ns16550%d: local queue full",
				    instance);
				freemsg(bp);
			} else
				(void) putq(q, bp);
	} else
		freemsg(bp);
	/*
	 * If we have a parity error, then send
	 * up an M_BREAK with the "bad"
	 * character as an argument. Let ldterm
	 * figure out what to do with the error.
	 */
	if (cc)
		(void) putctl1(q, M_BREAK, c);
	mutex_enter(&ns16550->ns16550_excl);
	mutex_enter(&ns16550->ns16550_excl_hi);
	if (cc) {
		NS16550SETSOFT(nsasync->nsasync_common); /* finish cc chars */
	}
rv:
	if ((RING_CNT(nsasync) < (RINGSIZE/4)) &&
	    (nsasync->nsasync_inflow_source & IN_FLOW_RINGBUFF)) {
		nsasync_flowcontrol_hw_input(ns16550, FLOW_START, IN_FLOW_RINGBUFF);
		(void) nsasync_flowcontrol_sw_input(ns16550, FLOW_START,
		    IN_FLOW_RINGBUFF);
	}

	/*
	 * If a transmission has finished, indicate that it's finished,
	 * and start that line up again.
	 */
	if (nsasync->nsasync_break > 0) {
		nb = nsasync->nsasync_break;
		nsasync->nsasync_break = 0;
		if (nsasync->nsasync_flags & NSASYNC_ISOPEN) {
			mutex_exit(&ns16550->ns16550_excl_hi);
			mutex_exit(&ns16550->ns16550_excl);
			for (; nb > 0; nb--)
				(void) putctl(q, M_BREAK);
			mutex_enter(&ns16550->ns16550_excl);
			mutex_enter(&ns16550->ns16550_excl_hi);
		}
	}
	if (nsasync->nsasync_ocnt <= 0 && (nsasync->nsasync_flags & NSASYNC_BUSY)) {
		DEBUGCONT2(NS16550_DEBUG_BUSY,
		    "nsasync%d_softint: Clearing NSASYNC_BUSY.  nsasync_ocnt=%d\n",
		    instance,
		    nsasync->nsasync_ocnt);
		nsasync->nsasync_flags &= ~NSASYNC_BUSY;
		mutex_exit(&ns16550->ns16550_excl_hi);
		if (nsasync->nsasync_xmitblk)
			freeb(nsasync->nsasync_xmitblk);
		nsasync->nsasync_xmitblk = NULL;
		nsasync_start(nsasync);
		/*
		 * If the flag isn't set after doing the nsasync_start above, we
		 * may have finished all the queued output.  Signal any thread
		 * stuck in close.
		 */
		if (!(nsasync->nsasync_flags & NSASYNC_BUSY))
			cv_broadcast(&nsasync->nsasync_flags_cv);
		mutex_enter(&ns16550->ns16550_excl_hi);
	}
	/*
	 * A note about these overrun bits: all they do is *tell* someone
	 * about an error- They do not track multiple errors. In fact,
	 * you could consider them latched register bits if you like.
	 * We are only interested in printing the error message once for
	 * any cluster of overrun errrors.
	 */
	if (nsasync->nsasync_hw_overrun) {
		if (nsasync->nsasync_flags & NSASYNC_ISOPEN) {
			mutex_exit(&ns16550->ns16550_excl_hi);
			mutex_exit(&ns16550->ns16550_excl);
			ns16550error(CE_NOTE, "ns16550%d: silo overflow", instance);
			mutex_enter(&ns16550->ns16550_excl);
			mutex_enter(&ns16550->ns16550_excl_hi);
		}
		nsasync->nsasync_hw_overrun = 0;
	}
	if (nsasync->nsasync_sw_overrun) {
		if (nsasync->nsasync_flags & NSASYNC_ISOPEN) {
			mutex_exit(&ns16550->ns16550_excl_hi);
			mutex_exit(&ns16550->ns16550_excl);
			ns16550error(CE_NOTE, "ns16550%d: ring buffer overflow",
			    instance);
			mutex_enter(&ns16550->ns16550_excl);
			mutex_enter(&ns16550->ns16550_excl_hi);
		}
		nsasync->nsasync_sw_overrun = 0;
	}
	if (ns16550->ns16550_flags & NS16550_DOINGSOFT_RETRY) {
		mutex_exit(&ns16550->ns16550_excl);
		goto begin;
	}
	ns16550->ns16550_flags &= ~NS16550_DOINGSOFT;
	mutex_exit(&ns16550->ns16550_excl_hi);
	mutex_exit(&ns16550->ns16550_excl);
	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_softint: done\n", instance);
}

/*
 * Restart output on a line after a delay or break timer expired.
 */
static void
nsasync_restart(void *arg)
{
	struct nsasyncline *nsasync = (struct nsasyncline *)arg;
	struct ns16550com *ns16550 = nsasync->nsasync_common;
	uchar_t lcr;

	/*
	 * If break timer expired, turn off the break bit.
	 */
#ifdef DEBUG
	int instance = UNIT(nsasync->nsasync_dev);

	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_restart\n", instance);
#endif
	mutex_enter(&ns16550->ns16550_excl);
	/*
	 * If NSASYNC_OUT_SUSPEND is also set, we don't really
	 * clean the HW break, TIOCCBRK is responsible for this.
	 */
	if ((nsasync->nsasync_flags & NSASYNC_BREAK) &&
	    !(nsasync->nsasync_flags & NSASYNC_OUT_SUSPEND)) {
		mutex_enter(&ns16550->ns16550_excl_hi);
		ns16550_set_break(ns16550, B_FALSE);
		mutex_exit(&ns16550->ns16550_excl_hi);
	}
	nsasync->nsasync_flags &= ~(NSASYNC_DELAY|NSASYNC_BREAK);
	cv_broadcast(&nsasync->nsasync_flags_cv);
	nsasync_start(nsasync);

	mutex_exit(&ns16550->ns16550_excl);
}

static void
nsasync_start(struct nsasyncline *nsasync)
{
	nsasync_nstart(nsasync, 0);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
/*ARGSUSED*/
static void
nsasync_nstart(struct nsasyncline *nsasync, int mode)
{
	struct ns16550com *ns16550 = nsasync->nsasync_common;
	int cc;
	queue_t *q;
	mblk_t *bp;
	uchar_t *xmit_addr;
	uchar_t	val;
	boolean_t didsome;
	mblk_t *nbp;

#ifdef DEBUG
	int instance = UNIT(nsasync->nsasync_dev);

	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_nstart\n", instance);
#endif

	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	/*
	 * If the chip is busy (i.e., we're waiting for a break timeout
	 * to expire, or for the current transmission to finish, or for
	 * output to finish draining from chip), don't grab anything new.
	 */
	if (nsasync->nsasync_flags & (NSASYNC_BREAK|NSASYNC_BUSY)) {
		DEBUGCONT2((mode? NS16550_DEBUG_OUT : 0),
		    "nsasync%d_nstart: start %s.\n",
		    instance,
		    nsasync->nsasync_flags & NSASYNC_BREAK ? "break" : "busy");
		return;
	}

	/*
	 * Check only pended sw input flow control.
	 */
	mutex_enter(&ns16550->ns16550_excl_hi);
	nsasync_flowcontrol_sw_input(ns16550, FLOW_CHECK, IN_FLOW_NULL);
	mutex_exit(&ns16550->ns16550_excl_hi);

	/*
	 * If we're waiting for a delay timeout to expire, don't grab
	 * anything new.
	 */
	if (nsasync->nsasync_flags & NSASYNC_DELAY) {
		DEBUGCONT1((mode? NS16550_DEBUG_OUT : 0),
		    "nsasync%d_nstart: start NSASYNC_DELAY.\n", instance);
		return;
	}

	if ((q = nsasync->nsasync_ttycommon.t_writeq) == NULL) {
		DEBUGCONT1((mode? NS16550_DEBUG_OUT : 0),
		    "nsasync%d_nstart: start writeq is null.\n", instance);
		return;	/* not attached to a stream */
	}

	for (;;) {
		if ((bp = getq(q)) == NULL)
			return;	/* no data to transmit */

		/*
		 * We have a message block to work on.
		 * Check whether it's a break, a delay, or an ioctl (the latter
		 * occurs if the ioctl in question was waiting for the output
		 * to drain).  If it's one of those, process it immediately.
		 */
		switch (bp->b_datap->db_type) {

		case M_BREAK:
			/*
			 * Set the break bit, and arrange for "nsasync_restart"
			 * to be called in 1/4 second; it will turn the
			 * break bit off, and call "nsasync_start" to grab
			 * the next message.
			 */
			mutex_enter(&ns16550->ns16550_excl_hi);
			ns16550_set_break(ns16550, B_TRUE);
			mutex_exit(&ns16550->ns16550_excl_hi);
			nsasync->nsasync_flags |= NSASYNC_BREAK;
			(void) timeout(nsasync_restart, (caddr_t)nsasync,
			    drv_usectohz(1000000)/4);
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_DELAY:
			/*
			 * Arrange for "nsasync_restart" to be called when the
			 * delay expires; it will turn NSASYNC_DELAY off,
			 * and call "nsasync_start" to grab the next message.
			 */
			(void) timeout(nsasync_restart, (caddr_t)nsasync,
			    (int)(*(unsigned char *)bp->b_rptr + 6));
			nsasync->nsasync_flags |= NSASYNC_DELAY;
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_IOCTL:
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Do it, and
			 * then grab the next message after it.
			 */
			mutex_exit(&ns16550->ns16550_excl);
			nsasync_ioctl(nsasync, q, bp);
			mutex_enter(&ns16550->ns16550_excl);
			continue;
		}

		while (bp != NULL && ((cc = MBLKL(bp)) == 0)) {
			nbp = bp->b_cont;
			freeb(bp);
			bp = nbp;
		}
		if (bp != NULL)
			break;
	}

	/*
	 * We have data to transmit.  If output is stopped, put
	 * it back and try again later.
	 */
	if (nsasync->nsasync_flags & (NSASYNC_HW_OUT_FLW | NSASYNC_SW_OUT_FLW |
	    NSASYNC_STOPPED | NSASYNC_OUT_SUSPEND)) {
		(void) putbq(q, bp);
		return;
	}

	nsasync->nsasync_xmitblk = bp;
	xmit_addr = bp->b_rptr;
	bp = bp->b_cont;
	if (bp != NULL)
		(void) putbq(q, bp);	/* not done with this message yet */

	/*
	 * In 5-bit mode, the high order bits are used
	 * to indicate character sizes less than five,
	 * so we need to explicitly mask before transmitting
	 */
	if ((nsasync->nsasync_ttycommon.t_cflag & CSIZE) == CS5) {
		unsigned char *p = xmit_addr;
		int cnt = cc;

		while (cnt--)
			*p++ &= (unsigned char) 0x1f;
	}

	/*
	 * Set up this block for pseudo-DMA.
	 */
	mutex_enter(&ns16550->ns16550_excl_hi);
	/*
	 * If the transmitter is ready, shove the first
	 * character out.
	 */
	didsome = B_FALSE;
	while (cc > 0) {
		if (!ns16550_tx_is_ready(ns16550))
			break;
		ns16550_put_char(ns16550, *xmit_addr++);
		cc--;
		didsome = B_TRUE;
	}
	nsasync->nsasync_optr = xmit_addr;
	nsasync->nsasync_ocnt = cc;
	if (didsome)
		nsasync->nsasync_flags |= NSASYNC_PROGRESS;
	DEBUGCONT2(NS16550_DEBUG_BUSY,
	    "nsasync%d_nstart: Set NSASYNC_BUSY.  nsasync_ocnt=%d\n",
	    instance, nsasync->nsasync_ocnt);
	nsasync->nsasync_flags |= NSASYNC_BUSY;
	if (cc == 0)
		NS16550SETSOFT(ns16550);

	mutex_exit(&ns16550->ns16550_excl_hi);
}

/*
 * Resume output by poking the transmitter.
 */
static void
nsasync_resume(struct nsasyncline *nsasync)
{
	struct ns16550com *ns16550 = nsasync->nsasync_common;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));
#ifdef DEBUG
	instance = UNIT(nsasync->nsasync_dev);
	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_resume\n", instance);
#endif

	if (ns16550_tx_is_ready(ns16550)) {
		if (nsasync_flowcontrol_sw_input(ns16550, FLOW_CHECK, IN_FLOW_NULL))
			return;
		if (nsasync->nsasync_ocnt > 0 &&
		    !(nsasync->nsasync_flags &
		    (NSASYNC_HW_OUT_FLW|NSASYNC_SW_OUT_FLW|NSASYNC_OUT_SUSPEND))) {
			ns16550_put_char(ns16550, *nsasync->nsasync_optr++);
			nsasync->nsasync_ocnt--;
			nsasync->nsasync_flags |= NSASYNC_PROGRESS;
		}
	}
}

/*
 * Hold the untimed break to last the minimum time.
 */
static void
nsasync_hold_utbrk(void *arg)
{
	struct nsasyncline *nsasync = arg;
	struct ns16550com *ns16550 = nsasync->nsasync_common;

	mutex_enter(&ns16550->ns16550_excl);
	nsasync->nsasync_flags &= ~NSASYNC_HOLD_UTBRK;
	cv_broadcast(&nsasync->nsasync_flags_cv);
	nsasync->nsasync_utbrktid = 0;
	mutex_exit(&ns16550->ns16550_excl);
}

/*
 * Resume the untimed break.
 */
static void
nsasync_resume_utbrk(struct nsasyncline *nsasync)
{
	uchar_t	val;
	struct ns16550com *ns16550 = nsasync->nsasync_common;
	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	/*
	 * Because the wait time is very short,
	 * so we use uninterruptably wait.
	 */
	while (nsasync->nsasync_flags & NSASYNC_HOLD_UTBRK) {
		cv_wait(&nsasync->nsasync_flags_cv, &ns16550->ns16550_excl);
	}
	mutex_enter(&ns16550->ns16550_excl_hi);
	/*
	 * Timed break and untimed break can exist simultaneously,
	 * if NSASYNC_BREAK is also set at here, we don't
	 * really clean the HW break.
	 */
	if (!(nsasync->nsasync_flags & NSASYNC_BREAK)) {
		ns16550_set_break(ns16550, B_FALSE);
	}
	nsasync->nsasync_flags &= ~NSASYNC_OUT_SUSPEND;
	cv_broadcast(&nsasync->nsasync_flags_cv);
	if (nsasync->nsasync_ocnt > 0) {
		nsasync_resume(nsasync);
		mutex_exit(&ns16550->ns16550_excl_hi);
	} else {
		nsasync->nsasync_flags &= ~NSASYNC_BUSY;
		mutex_exit(&ns16550->ns16550_excl_hi);
		if (nsasync->nsasync_xmitblk != NULL) {
			freeb(nsasync->nsasync_xmitblk);
			nsasync->nsasync_xmitblk = NULL;
		}
		nsasync_start(nsasync);
	}
}

/*
 * Process an "ioctl" message sent down to us.
 * Note that we don't need to get any locks until we are ready to access
 * the hardware.  Nothing we access until then is going to be altered
 * outside of the STREAMS framework, so we should be safe.
 */
int ns16550delay = 10000;
static void
nsasync_ioctl(struct nsasyncline *nsasync, queue_t *wq, mblk_t *mp)
{
	struct ns16550com *ns16550 = nsasync->nsasync_common;
	tty_common_t  *tp = &nsasync->nsasync_ttycommon;
	struct iocblk *iocp;
	unsigned datasize;
	int error = 0;
	uchar_t val;
	mblk_t *datamp;
	unsigned int index;

#ifdef DEBUG
	int instance = UNIT(nsasync->nsasync_dev);

	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_ioctl\n", instance);
#endif

	if (tp->t_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(nsasync->nsasync_ttycommon.t_iocpending);
		nsasync->nsasync_ttycommon.t_iocpending = NULL;
	}

	iocp = (struct iocblk *)mp->b_rptr;

	/*
	 * For TIOCMGET and the PPS ioctls, do NOT call ttycommon_ioctl()
	 * because this function frees up the message block (mp->b_cont) that
	 * contains the user location where we pass back the results.
	 *
	 * Similarly, CONSOPENPOLLEDIO needs ioc_count, which ttycommon_ioctl
	 * zaps.  We know that ttycommon_ioctl doesn't know any CONS*
	 * ioctls, so keep the others safe too.
	 */
	DEBUGCONT2(NS16550_DEBUG_IOCTL, "nsasync%d_ioctl: %s\n",
	    instance,
	    iocp->ioc_cmd == TIOCMGET ? "TIOCMGET" :
	    iocp->ioc_cmd == TIOCMSET ? "TIOCMSET" :
	    iocp->ioc_cmd == TIOCMBIS ? "TIOCMBIS" :
	    iocp->ioc_cmd == TIOCMBIC ? "TIOCMBIC" :
	    "other");

	switch (iocp->ioc_cmd) {
	case TIOCMGET:
	case TIOCGPPS:
	case TIOCSPPS:
	case TIOCGPPSEV:
	case CONSOPENPOLLEDIO:
	case CONSCLOSEPOLLEDIO:
	case CONSSETABORTENABLE:
	case CONSGETABORTENABLE:
		error = -1; /* Do Nothing */
		break;
	default:

		/*
		 * The only way in which "ttycommon_ioctl" can fail is if the
		 * "ioctl" requires a response containing data to be returned
		 * to the user, and no mblk could be allocated for the data.
		 * No such "ioctl" alters our state.  Thus, we always go ahead
		 * and do any state-changes the "ioctl" calls for.  If we
		 * couldn't allocate the data, "ttycommon_ioctl" has stashed
		 * the "ioctl" away safely, so we just call "bufcall" to
		 * request that we be called back when we stand a better
		 * chance of allocating the data.
		 */
		if ((datasize = ttycommon_ioctl(tp, wq, mp, &error)) != 0) {
			if (nsasync->nsasync_wbufcid)
				unbufcall(nsasync->nsasync_wbufcid);
			nsasync->nsasync_wbufcid = bufcall(datasize, BPRI_HI,
			    (void (*)(void *)) nsasync_reioctl,
			    (void *)(intptr_t)nsasync->nsasync_common->ns16550_unit);
			return;
		}
	}

	mutex_enter(&ns16550->ns16550_excl);

	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (iocp->ioc_cmd) {

		case TCSETS:
			mutex_enter(&ns16550->ns16550_excl_hi);
			if (ns16550_baudok(ns16550))
				ns16550_program(ns16550, NS16550_NOINIT);
			else
				error = EINVAL;
			mutex_exit(&ns16550->ns16550_excl_hi);
			break;
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			mutex_enter(&ns16550->ns16550_excl_hi);
			if (!ns16550_baudok(ns16550))
				error = EINVAL;
			else {
				if (ns16550_isbusy(ns16550))
					ns16550_waiteot(ns16550);
				ns16550_program(ns16550, NS16550_NOINIT);
			}
			mutex_exit(&ns16550->ns16550_excl_hi);
			break;
		}
	} else if (error < 0) {
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {

		case TIOCGPPS:
			/*
			 * Get PPS on/off.
			 */
			if (mp->b_cont != NULL)
				freemsg(mp->b_cont);

			mp->b_cont = allocb(sizeof (int), BPRI_HI);
			if (mp->b_cont == NULL) {
				error = ENOMEM;
				break;
			}
			if (ns16550->ns16550_flags & NS16550_PPS)
				*(int *)mp->b_cont->b_wptr = 1;
			else
				*(int *)mp->b_cont->b_wptr = 0;
			mp->b_cont->b_wptr += sizeof (int);
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = sizeof (int);
			break;

		case TIOCSPPS:
			/*
			 * Set PPS on/off.
			 */
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			mutex_enter(&ns16550->ns16550_excl_hi);
			if (*(int *)mp->b_cont->b_rptr)
				ns16550->ns16550_flags |= NS16550_PPS;
			else
				ns16550->ns16550_flags &= ~NS16550_PPS;
			/* Reset edge sense */
			ns16550->ns16550_flags &= ~NS16550_PPS_EDGE;
			mutex_exit(&ns16550->ns16550_excl_hi);
			mp->b_datap->db_type = M_IOCACK;
			break;

		case TIOCGPPSEV:
		{
			/*
			 * Get PPS event data.
			 */
			mblk_t *bp;
			void *buf;
			struct ppsclockev ppsclockev;

			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}

			if ((ns16550->ns16550_flags & NS16550_PPS) == 0) {
				error = ENXIO;
				break;
			}

			/* Protect from incomplete ns16550_ppsev */
			mutex_enter(&ns16550->ns16550_excl_hi);
			ppsclockev = ns16550_ppsev;
			mutex_exit(&ns16550->ns16550_excl_hi);

			buf = &ppsclockev;
			iocp->ioc_count = sizeof (struct ppsclockev);

			if ((bp = allocb(iocp->ioc_count, BPRI_HI)) == NULL) {
				error = ENOMEM;
				break;
			}
			mp->b_cont = bp;

			bcopy(buf, bp->b_wptr, iocp->ioc_count);
			bp->b_wptr += iocp->ioc_count;
			mp->b_datap->db_type = M_IOCACK;
			break;
		}

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			if (*(int *)mp->b_cont->b_rptr == 0) {

				/*
				 * XXX Arrangements to ensure that a break
				 * isn't in progress should be sufficient.
				 * This ugly delay() is the only thing
				 * that seems to work on the NCR Worldmark.
				 * It should be replaced. Note that an
				 * ns16550_waiteot() also does not work.
				 */
				if (ns16550delay)
					delay(drv_usectohz(ns16550delay));

				while (nsasync->nsasync_flags & NSASYNC_BREAK) {
					cv_wait(&nsasync->nsasync_flags_cv,
					    &ns16550->ns16550_excl);
				}
				mutex_enter(&ns16550->ns16550_excl_hi);
				/*
				 * We loop until the TSR is empty and then
				 * set the break.  NSASYNC_BREAK has been set
				 * to ensure that no characters are
				 * transmitted while the TSR is being
				 * flushed and SOUT is being used for the
				 * break signal.
				 *
				 * The wait period is equal to
				 * clock / (baud * 16) * 16 * 2.
				 */
				index = BAUDINDEX(
				    nsasync->nsasync_ttycommon.t_cflag);
				nsasync->nsasync_flags |= NSASYNC_BREAK;

				while (ns16550_is_busy(ns16550)) {
					mutex_exit(&ns16550->ns16550_excl_hi);
					mutex_exit(&ns16550->ns16550_excl);
					drv_usecwait(ns16550->ns16550_clock / baudtable[index] * 2);
					mutex_enter(&ns16550->ns16550_excl);
					mutex_enter(&ns16550->ns16550_excl_hi);
				}
				/*
				 * Arrange for "nsasync_restart"
				 * to be called in 1/4 second;
				 * it will turn the break bit off, and call
				 * "nsasync_start" to grab the next message.
				 */
				ns16550_set_break(ns16550, B_TRUE);
				mutex_exit(&ns16550->ns16550_excl_hi);
				(void) timeout(nsasync_restart, (caddr_t)nsasync,
				    drv_usectohz(1000000)/4);
			} else {
				DEBUGCONT1(NS16550_DEBUG_OUT,
				    "nsasync%d_ioctl: wait for flush.\n",
				    instance);
				mutex_enter(&ns16550->ns16550_excl_hi);
				ns16550_waiteot(ns16550);
				mutex_exit(&ns16550->ns16550_excl_hi);
				DEBUGCONT1(NS16550_DEBUG_OUT,
				    "nsasync%d_ioctl: ldterm satisfied.\n",
				    instance);
			}
			break;

		case TIOCSBRK:
			if (!(nsasync->nsasync_flags & NSASYNC_OUT_SUSPEND)) {
				mutex_enter(&ns16550->ns16550_excl_hi);
				nsasync->nsasync_flags |= NSASYNC_OUT_SUSPEND;
				nsasync->nsasync_flags |= NSASYNC_HOLD_UTBRK;
				index = BAUDINDEX(
				    nsasync->nsasync_ttycommon.t_cflag);
				while (ns16550_is_busy(ns16550)) {
					mutex_exit(&ns16550->ns16550_excl_hi);
					mutex_exit(&ns16550->ns16550_excl);
					drv_usecwait(ns16550->ns16550_clock / baudtable[index] * 2);
					mutex_enter(&ns16550->ns16550_excl);
					mutex_enter(&ns16550->ns16550_excl_hi);
				}
				ns16550_set_break(ns16550, B_TRUE);
				mutex_exit(&ns16550->ns16550_excl_hi);
				/* wait for 100ms to hold BREAK */
				nsasync->nsasync_utbrktid =
				    timeout((void (*)())nsasync_hold_utbrk,
				    (caddr_t)nsasync,
				    drv_usectohz(ns16550_min_utbrk));
			}
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCCBRK:
			if (nsasync->nsasync_flags & NSASYNC_OUT_SUSPEND)
				nsasync_resume_utbrk(nsasync);
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count != TRANSPARENT) {
				DEBUGCONT1(NS16550_DEBUG_IOCTL, "nsasync%d_ioctl: "
				    "non-transparent\n", instance);

				error = miocpullup(mp, sizeof (int));
				if (error != 0)
					break;

				mutex_enter(&ns16550->ns16550_excl_hi);
				(void) ns16550mctl(ns16550,
				    dmtons16550(*(int *)mp->b_cont->b_rptr),
				    iocp->ioc_cmd);
				mutex_exit(&ns16550->ns16550_excl_hi);
				iocp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			} else {
				DEBUGCONT1(NS16550_DEBUG_IOCTL, "nsasync%d_ioctl: "
				    "transparent\n", instance);
				mcopyin(mp, NULL, sizeof (int), NULL);
			}
			break;

		case TIOCMGET:
			datamp = allocb(sizeof (int), BPRI_MED);
			if (datamp == NULL) {
				error = EAGAIN;
				break;
			}

			mutex_enter(&ns16550->ns16550_excl_hi);
			*(int *)datamp->b_rptr = ns16550mctl(ns16550, 0, TIOCMGET);
			mutex_exit(&ns16550->ns16550_excl_hi);

			if (iocp->ioc_count == TRANSPARENT) {
				DEBUGCONT1(NS16550_DEBUG_IOCTL, "nsasync%d_ioctl: "
				    "transparent\n", instance);
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			} else {
				DEBUGCONT1(NS16550_DEBUG_IOCTL, "nsasync%d_ioctl: "
				    "non-transparent\n", instance);
				mioc2ack(mp, datamp, sizeof (int), 0);
			}
			break;

		case CONSOPENPOLLEDIO:
			error = miocpullup(mp, sizeof (struct cons_polledio *));
			if (error != 0)
				break;

			*(struct cons_polledio **)mp->b_cont->b_rptr =
			    &ns16550->polledio;

			mp->b_datap->db_type = M_IOCACK;
			break;

		case CONSCLOSEPOLLEDIO:
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSSETABORTENABLE:
			error = secpolicy_console(iocp->ioc_cr);
			if (error != 0)
				break;

			if (iocp->ioc_count != TRANSPARENT) {
				error = EINVAL;
				break;
			}

			mutex_enter(&ns16550->ns16550_excl_hi);
			if (*(intptr_t *)mp->b_cont->b_rptr)
				ns16550->ns16550_flags |= NS16550_CONSOLE;
			else
				ns16550->ns16550_flags &= ~NS16550_CONSOLE;
			mutex_exit(&ns16550->ns16550_excl_hi);

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSGETABORTENABLE:
			/*CONSTANTCONDITION*/
			ASSERT(sizeof (boolean_t) <= sizeof (boolean_t *));
			/*
			 * Store the return value right in the payload
			 * we were passed.  Crude.
			 */
			mcopyout(mp, NULL, sizeof (boolean_t), NULL, NULL);
			*(boolean_t *)mp->b_cont->b_rptr =
			    (ns16550->ns16550_flags & NS16550_CONSOLE) != 0;
			break;

		default:
			/*
			 * If we don't understand it, it's an error.  NAK it.
			 */
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	mutex_exit(&ns16550->ns16550_excl);
	qreply(wq, mp);
	DEBUGCONT1(NS16550_DEBUG_PROCS, "nsasync%d_ioctl: done\n", instance);
}

static int
ns16550rsrv(queue_t *q)
{
	mblk_t *bp;
	struct nsasyncline *nsasync;
	struct ns16550com *ns16550;

	nsasync = (struct nsasyncline *)q->q_ptr;
	ns16550 = nsasync->nsasync_common;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);

	mutex_enter(&ns16550->ns16550_excl_hi);
	NS16550SETSOFT(ns16550);
	mutex_exit(&ns16550->ns16550_excl_hi);
	nsasync->nsasync_polltid = 0;
	return (0);
}

/*
 * The NS16550WPUTDO_NOT_SUSP macro indicates to ns16550wputdo() whether it should
 * handle messages as though the driver is operating normally or is
 * suspended.  In the suspended case, some or all of the processing may have
 * to be delayed until the driver is resumed.
 */
#define	NS16550WPUTDO_NOT_SUSP(nsasync, wput) \
	!((wput) && ((nsasync)->nsasync_flags & NSASYNC_DDI_SUSPENDED))

/*
 * Processing for write queue put procedure.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * set the flow control character for M_STOPI and M_STARTI messages;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing
 * by the start routine, and then call the start routine; discard
 * everything else.  Note that this driver does not incorporate any
 * mechanism to negotiate to handle the canonicalization process.
 * It expects that these functions are handled in upper module(s),
 * as we do in ldterm.
 */
static int
ns16550wputdo(queue_t *q, mblk_t *mp, boolean_t wput)
{
	struct nsasyncline *nsasync;
	struct ns16550com *ns16550;
#ifdef DEBUG
	int instance;
#endif
	int error;

	nsasync = (struct nsasyncline *)q->q_ptr;

#ifdef DEBUG
	instance = UNIT(nsasync->nsasync_dev);
#endif
	ns16550 = nsasync->nsasync_common;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		/*
		 * Since we don't do real DMA, we can just let the
		 * chip coast to a stop after applying the brakes.
		 */
		mutex_enter(&ns16550->ns16550_excl);
		nsasync->nsasync_flags |= NSASYNC_STOPPED;
		mutex_exit(&ns16550->ns16550_excl);
		freemsg(mp);
		break;

	case M_START:
		mutex_enter(&ns16550->ns16550_excl);
		if (nsasync->nsasync_flags & NSASYNC_STOPPED) {
			nsasync->nsasync_flags &= ~NSASYNC_STOPPED;
			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				/*
				 * If an output operation is in progress,
				 * resume it.  Otherwise, prod the start
				 * routine.
				 */
				if (nsasync->nsasync_ocnt > 0) {
					mutex_enter(&ns16550->ns16550_excl_hi);
					nsasync_resume(nsasync);
					mutex_exit(&ns16550->ns16550_excl_hi);
				} else {
					nsasync_start(nsasync);
				}
			}
		}
		mutex_exit(&ns16550->ns16550_excl);
		freemsg(mp);
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return (0);
			}

			if (*(int *)mp->b_cont->b_rptr != 0) {
				DEBUGCONT1(NS16550_DEBUG_OUT,
				    "nsasync%d_ioctl: flush request.\n",
				    instance);
				(void) putq(q, mp);

				mutex_enter(&ns16550->ns16550_excl);
				if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
					/*
					 * If an TIOCSBRK is in progress,
					 * clean it as TIOCCBRK does,
					 * then kick off output.
					 * If TIOCSBRK is not in progress,
					 * just kick off output.
					 */
					nsasync_resume_utbrk(nsasync);
				}
				mutex_exit(&ns16550->ns16550_excl);
				break;
			}
			/*FALLTHROUGH*/
		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
			/*
			 * The changes do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "nsasync_start" will see it when it's done
			 * with the output before it.  Poke the
			 * start routine, just in case.
			 */
			(void) putq(q, mp);

			mutex_enter(&ns16550->ns16550_excl);
			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				/*
				 * If an TIOCSBRK is in progress,
				 * clean it as TIOCCBRK does.
				 * then kick off output.
				 * If TIOCSBRK is not in progress,
				 * just kick off output.
				 */
				nsasync_resume_utbrk(nsasync);
			}
			mutex_exit(&ns16550->ns16550_excl);
			break;

		default:
			/*
			 * Do it now.
			 */
			mutex_enter(&ns16550->ns16550_excl);
			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				mutex_exit(&ns16550->ns16550_excl);
				nsasync_ioctl(nsasync, q, mp);
				break;
			}
			nsasync_put_suspq(ns16550, mp);
			mutex_exit(&ns16550->ns16550_excl);
			break;
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&ns16550->ns16550_excl);

			/*
			 * Abort any output in progress.
			 */
			mutex_enter(&ns16550->ns16550_excl_hi);
			if (nsasync->nsasync_flags & NSASYNC_BUSY) {
				DEBUGCONT1(NS16550_DEBUG_BUSY, "ns16550%dwput: "
				    "Clearing nsasync_ocnt, "
				    "leaving NSASYNC_BUSY set\n",
				    instance);
				nsasync->nsasync_ocnt = 0;
				nsasync->nsasync_flags &= ~NSASYNC_BUSY;
			} /* if */

			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				/* Flush FIFO buffers */
				ns16550_reset_fifo(ns16550, FIFOTXFLSH);
			}
			mutex_exit(&ns16550->ns16550_excl_hi);

			/* Flush FIFO buffers */
			ns16550_reset_fifo(ns16550, FIFOTXFLSH);

			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			if (nsasync->nsasync_xmitblk != NULL) {
				freeb(nsasync->nsasync_xmitblk);
				nsasync->nsasync_xmitblk = NULL;
			}
			mutex_exit(&ns16550->ns16550_excl);
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				/* Flush FIFO buffers */
				ns16550_reset_fifo(ns16550, FIFORXFLSH);
			}
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else {
			freemsg(mp);
		}

		/*
		 * We must make sure we process messages that survive the
		 * write-side flush.
		 */
		if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
			mutex_enter(&ns16550->ns16550_excl);
			nsasync_start(nsasync);
			mutex_exit(&ns16550->ns16550_excl);
		}
		break;

	case M_BREAK:
	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
			mutex_enter(&ns16550->ns16550_excl);
			nsasync_start(nsasync);
			mutex_exit(&ns16550->ns16550_excl);
		}
		break;

	case M_STOPI:
		mutex_enter(&ns16550->ns16550_excl);
		if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
			mutex_enter(&ns16550->ns16550_excl_hi);
			if (!(nsasync->nsasync_inflow_source & IN_FLOW_USER)) {
				nsasync_flowcontrol_hw_input(ns16550, FLOW_STOP,
				    IN_FLOW_USER);
				(void) nsasync_flowcontrol_sw_input(ns16550,
				    FLOW_STOP, IN_FLOW_USER);
			}
			mutex_exit(&ns16550->ns16550_excl_hi);
			mutex_exit(&ns16550->ns16550_excl);
			freemsg(mp);
			break;
		}
		nsasync_put_suspq(ns16550, mp);
		mutex_exit(&ns16550->ns16550_excl);
		break;

	case M_STARTI:
		mutex_enter(&ns16550->ns16550_excl);
		if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
			mutex_enter(&ns16550->ns16550_excl_hi);
			if (nsasync->nsasync_inflow_source & IN_FLOW_USER) {
				nsasync_flowcontrol_hw_input(ns16550, FLOW_START,
				    IN_FLOW_USER);
				(void) nsasync_flowcontrol_sw_input(ns16550,
				    FLOW_START, IN_FLOW_USER);
			}
			mutex_exit(&ns16550->ns16550_excl_hi);
			mutex_exit(&ns16550->ns16550_excl);
			freemsg(mp);
			break;
		}
		nsasync_put_suspq(ns16550, mp);
		mutex_exit(&ns16550->ns16550_excl);
		break;

	case M_CTL:
		if (MBLKL(mp) >= sizeof (struct iocblk) &&
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_POSIXQUERY) {
			mutex_enter(&ns16550->ns16550_excl);
			if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
				((struct iocblk *)mp->b_rptr)->ioc_cmd =
				    MC_HAS_POSIX;
				mutex_exit(&ns16550->ns16550_excl);
				qreply(q, mp);
				break;
			} else {
				nsasync_put_suspq(ns16550, mp);
			}
		} else {
			/*
			 * These MC_SERVICE type messages are used by upper
			 * modules to tell this driver to send input up
			 * immediately, or that it can wait for normal
			 * processing that may or may not be done.  Sun
			 * requires these for the mouse module.
			 * (XXX - for x86?)
			 */
			mutex_enter(&ns16550->ns16550_excl);
			switch (*mp->b_rptr) {

			case MC_SERVICEIMM:
				nsasync->nsasync_flags |= NSASYNC_SERVICEIMM;
				break;

			case MC_SERVICEDEF:
				nsasync->nsasync_flags &= ~NSASYNC_SERVICEIMM;
				break;
			}
			mutex_exit(&ns16550->ns16550_excl);
			freemsg(mp);
		}
		break;

	case M_IOCDATA:
		mutex_enter(&ns16550->ns16550_excl);
		if (NS16550WPUTDO_NOT_SUSP(nsasync, wput)) {
			mutex_exit(&ns16550->ns16550_excl);
			nsasync_iocdata(q, mp);
			break;
		}
		nsasync_put_suspq(ns16550, mp);
		mutex_exit(&ns16550->ns16550_excl);
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static int
ns16550wput(queue_t *q, mblk_t *mp)
{
	return (ns16550wputdo(q, mp, B_TRUE));
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
nsasync_reioctl(void *unit)
{
	int instance = (uintptr_t)unit;
	struct nsasyncline *nsasync;
	struct ns16550com *ns16550;
	queue_t	*q;
	mblk_t	*mp;

	ns16550 = ddi_get_soft_state(ns16550_soft_state, instance);
	ASSERT(ns16550 != NULL);
	nsasync = ns16550->ns16550_priv;

	/*
	 * The bufcall is no longer pending.
	 */
	mutex_enter(&ns16550->ns16550_excl);
	nsasync->nsasync_wbufcid = 0;
	if ((q = nsasync->nsasync_ttycommon.t_writeq) == NULL) {
		mutex_exit(&ns16550->ns16550_excl);
		return;
	}
	if ((mp = nsasync->nsasync_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		nsasync->nsasync_ttycommon.t_iocpending = NULL;
		mutex_exit(&ns16550->ns16550_excl);
		nsasync_ioctl(nsasync, q, mp);
	} else
		mutex_exit(&ns16550->ns16550_excl);
}

static void
nsasync_iocdata(queue_t *q, mblk_t *mp)
{
	struct nsasyncline	*nsasync = (struct nsasyncline *)q->q_ptr;
	struct ns16550com		*ns16550;
	struct iocblk *ip;
	struct copyresp *csp;
#ifdef DEBUG
	int instance = UNIT(nsasync->nsasync_dev);
#endif

	ns16550 = nsasync->nsasync_common;
	ip = (struct iocblk *)mp->b_rptr;
	csp = (struct copyresp *)mp->b_rptr;

	if (csp->cp_rval != 0) {
		if (csp->cp_private)
			freemsg(csp->cp_private);
		freemsg(mp);
		return;
	}

	mutex_enter(&ns16550->ns16550_excl);
	DEBUGCONT2(NS16550_DEBUG_MODEM, "nsasync%d_iocdata: case %s\n",
	    instance,
	    csp->cp_cmd == TIOCMGET ? "TIOCMGET" :
	    csp->cp_cmd == TIOCMSET ? "TIOCMSET" :
	    csp->cp_cmd == TIOCMBIS ? "TIOCMBIS" :
	    "TIOCMBIC");
	switch (csp->cp_cmd) {

	case TIOCMGET:
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_datap->db_type = M_IOCACK;
		ip->ioc_error = 0;
		ip->ioc_count = 0;
		ip->ioc_rval = 0;
		mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
		break;

	case TIOCMSET:
	case TIOCMBIS:
	case TIOCMBIC:
		mutex_enter(&ns16550->ns16550_excl_hi);
		(void) ns16550mctl(ns16550, dmtons16550(*(int *)mp->b_cont->b_rptr),
		    csp->cp_cmd);
		mutex_exit(&ns16550->ns16550_excl_hi);
		mioc2ack(mp, NULL, 0, 0);
		break;

	default:
		mp->b_datap->db_type = M_IOCNAK;
		ip->ioc_error = EINVAL;
		break;
	}
	qreply(q, mp);
	mutex_exit(&ns16550->ns16550_excl);
}

/*
 * debugger/console support routines.
 */

/*
 * put a character out
 * Do not use interrupts.  If char is LF, put out CR, LF.
 */
static void
ns16550putchar(cons_polledio_arg_t arg, uchar_t c)
{
	struct ns16550com *ns16550 = (struct ns16550com *)arg;

	if (c == '\n')
		ns16550putchar(arg, '\r');

	while (!ns16550_tx_is_ready(ns16550)) {
		/* wait for xmit to finish */
		drv_usecwait(10);
	}

	/* put the character out */
	ns16550_put_char(ns16550, c);
}

/*
 * See if there's a character available. If no character is
 * available, return 0. Run in polled mode, no interrupts.
 */
static boolean_t
ns16550ischar(cons_polledio_arg_t arg)
{
	struct ns16550com *ns16550 = (struct ns16550com *)arg;

	return ns16550_rx_is_ready(ns16550);
}

/*
 * Get a character. Run in polled mode, no interrupts.
 */
static int
ns16550getchar(cons_polledio_arg_t arg)
{
	struct ns16550com *ns16550 = (struct ns16550com *)arg;

	while (!ns16550ischar(arg))
		drv_usecwait(10);
	return (ns16550_get_char(ns16550));
}

/*
 * Set or get the modem control status.
 */
static int
ns16550mctl(struct ns16550com *ns16550, int bits, int how)
{
	int mcr_r, msr_r;
	int instance = ns16550->ns16550_unit;

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));
	ASSERT(mutex_owned(&ns16550->ns16550_excl));

	/* Read Modem Control Registers */
	mcr_r = ns16550_get_mcr(ns16550);

	switch (how) {

	case TIOCMSET:
		DEBUGCONT2(NS16550_DEBUG_MODEM,
		    "ns16550%dmctl: TIOCMSET, bits = %x\n", instance, bits);
		mcr_r = bits;		/* Set bits	*/
		break;

	case TIOCMBIS:
		DEBUGCONT2(NS16550_DEBUG_MODEM, "ns16550%dmctl: TIOCMBIS, bits = %x\n",
		    instance, bits);
		mcr_r |= bits;		/* Mask in bits	*/
		break;

	case TIOCMBIC:
		DEBUGCONT2(NS16550_DEBUG_MODEM, "ns16550%dmctl: TIOCMBIC, bits = %x\n",
		    instance, bits);
		mcr_r &= ~bits;		/* Mask out bits */
		break;

	case TIOCMGET:
		/* Read Modem Status Registers */
		/*
		 * If modem interrupts are enabled, we return the
		 * saved value of msr. We read MSR only in nsasync_msint()
		 */
		if (ns16550_get_icr(ns16550) & MIEN) {
			msr_r = ns16550->ns16550_msr;
			DEBUGCONT2(NS16550_DEBUG_MODEM,
			    "ns16550%dmctl: TIOCMGET, read msr_r = %x\n",
			    instance, msr_r);
		} else {
			msr_r = ns16550_get_msr(ns16550);
			DEBUGCONT2(NS16550_DEBUG_MODEM,
			    "ns16550%dmctl: TIOCMGET, read MSR = %x\n",
			    instance, msr_r);
		}
		DEBUGCONT2(NS16550_DEBUG_MODEM, "ns16550%dtodm: modem_lines = %x\n",
		    instance, ns16550todm(mcr_r, msr_r));
		return (ns16550todm(mcr_r, msr_r));
	}

	ns16550_set_mcr(ns16550, mcr_r);

	return (mcr_r);
}

static int
ns16550todm(int mcr_r, int msr_r)
{
	int b = 0;

	/* MCR registers */
	if (mcr_r & RTS)
		b |= TIOCM_RTS;

	if (mcr_r & DTR)
		b |= TIOCM_DTR;

	/* MSR registers */
	if (msr_r & DCD)
		b |= TIOCM_CAR;

	if (msr_r & CTS)
		b |= TIOCM_CTS;

	if (msr_r & DSR)
		b |= TIOCM_DSR;

	if (msr_r & RI)
		b |= TIOCM_RNG;
	return (b);
}

static int
dmtons16550(int bits)
{
	int b = 0;

	DEBUGCONT1(NS16550_DEBUG_MODEM, "dmtons16550: bits = %x\n", bits);
#ifdef	CAN_NOT_SET	/* only DTR and RTS can be set */
	if (bits & TIOCM_CAR)
		b |= DCD;
	if (bits & TIOCM_CTS)
		b |= CTS;
	if (bits & TIOCM_DSR)
		b |= DSR;
	if (bits & TIOCM_RNG)
		b |= RI;
#endif

	if (bits & TIOCM_RTS) {
		DEBUGCONT0(NS16550_DEBUG_MODEM, "dmtons16550: set b & RTS\n");
		b |= RTS;
	}
	if (bits & TIOCM_DTR) {
		DEBUGCONT0(NS16550_DEBUG_MODEM, "dmtons16550: set b & DTR\n");
		b |= DTR;
	}

	return (b);
}

static void
ns16550error(int level, const char *fmt, ...)
{
	va_list adx;
	static	time_t	last;
	static	const char *lastfmt;
	time_t	now;

	/*
	 * Don't print the same error message too often.
	 * Print the message only if we have not printed the
	 * message within the last second.
	 * Note: that fmt cannot be a pointer to a string
	 * stored on the stack. The fmt pointer
	 * must be in the data segment otherwise lastfmt would point
	 * to non-sense.
	 */
	now = gethrestime_sec();
	if (last == now && lastfmt == fmt)
		return;

	last = now;
	lastfmt = fmt;

	va_start(adx, fmt);
	vcmn_err(level, fmt, adx);
	va_end(adx);
}

/*
 * ns16550_parse_mode(dev_info_t *devi, struct ns16550com *ns16550)
 * The value of this property is in the form of "9600,8,n,1,-"
 * 1) speed: 9600, 4800, ...
 * 2) data bits
 * 3) parity: n(none), e(even), o(odd)
 * 4) stop bits
 * 5) handshake: -(none), h(hardware: rts/cts), s(software: xon/off)
 *
 * This parsing came from a SPARCstation eeprom.
 */
static void
ns16550_parse_mode(dev_info_t *devi, struct ns16550com *ns16550)
{
	char		name[40];
	char		val[40];
	int		len;
	int		ret;
	char		*p;
	char		*p1;

	ASSERT(ns16550->ns16550_com_port != 0);

	/*
	 * Parse the ttyx-mode property
	 */
	(void) sprintf(name, "tty%c-mode", ns16550->ns16550_com_port + 'a' - 1);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-mode", ns16550->ns16550_com_port + '0');
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}

	/* no property to parse */
	ns16550->ns16550_cflag = 0;
	if (ret != DDI_PROP_SUCCESS)
		return;

	p = val;
	/* ---- baud rate ---- */
	ns16550->ns16550_cflag = CREAD |
	    (NS16550_DEFAULT_BAUD & CBAUD) |
	    (NS16550_DEFAULT_BAUD > CBAUD? CBAUDEXT: 0);		/* initial default */
	if (p && (p1 = strchr(p, ',')) != 0) {
		*p1++ = '\0';
	} else {
		ns16550->ns16550_cflag |= BITS8;	/* add default bits */
		return;
	}

	if (strcmp(p, "110") == 0)
		ns16550->ns16550_bidx = B110;
	else if (strcmp(p, "150") == 0)
		ns16550->ns16550_bidx = B150;
	else if (strcmp(p, "300") == 0)
		ns16550->ns16550_bidx = B300;
	else if (strcmp(p, "600") == 0)
		ns16550->ns16550_bidx = B600;
	else if (strcmp(p, "1200") == 0)
		ns16550->ns16550_bidx = B1200;
	else if (strcmp(p, "2400") == 0)
		ns16550->ns16550_bidx = B2400;
	else if (strcmp(p, "4800") == 0)
		ns16550->ns16550_bidx = B4800;
	else if (strcmp(p, "9600") == 0)
		ns16550->ns16550_bidx = B9600;
	else if (strcmp(p, "19200") == 0)
		ns16550->ns16550_bidx = B19200;
	else if (strcmp(p, "38400") == 0)
		ns16550->ns16550_bidx = B38400;
	else if (strcmp(p, "57600") == 0)
		ns16550->ns16550_bidx = B57600;
	else if (strcmp(p, "115200") == 0)
		ns16550->ns16550_bidx = B115200;
	else
		ns16550->ns16550_bidx = NS16550_DEFAULT_BAUD;

	ns16550->ns16550_cflag &= ~(CBAUD | CBAUDEXT);
	if (ns16550->ns16550_bidx > CBAUD) {	/* > 38400 uses the CBAUDEXT bit */
		ns16550->ns16550_cflag |= CBAUDEXT;
		ns16550->ns16550_cflag |= ns16550->ns16550_bidx - CBAUD - 1;
	} else {
		ns16550->ns16550_cflag |= ns16550->ns16550_bidx;
	}

	ASSERT(ns16550->ns16550_bidx == BAUDINDEX(ns16550->ns16550_cflag));

	/* ---- Next item is data bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		ns16550->ns16550_cflag |= BITS8;	/* add default bits */
		return;
	}
	switch (*p) {
		default:
		case '8':
			ns16550->ns16550_cflag |= CS8;
			ns16550->ns16550_lcr = BITS8;
			break;
		case '7':
			ns16550->ns16550_cflag |= CS7;
			ns16550->ns16550_lcr = BITS7;
			break;
		case '6':
			ns16550->ns16550_cflag |= CS6;
			ns16550->ns16550_lcr = BITS6;
			break;
		case '5':
			/* LINTED: CS5 is currently zero (but might change) */
			ns16550->ns16550_cflag |= CS5;
			ns16550->ns16550_lcr = BITS5;
			break;
	}

	/* ---- Parity info ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	switch (*p)  {
		default:
		case 'n':
			break;
		case 'e':
			ns16550->ns16550_cflag |= PARENB;
			ns16550->ns16550_lcr |= PEN; break;
		case 'o':
			ns16550->ns16550_cflag |= PARENB|PARODD;
			ns16550->ns16550_lcr |= PEN|EPS;
			break;
	}

	/* ---- Find stop bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	if (*p == '2') {
		ns16550->ns16550_cflag |= CSTOPB;
		ns16550->ns16550_lcr |= STB;
	}

	/* ---- handshake is next ---- */
	p = p1;
	if (p) {
		if ((p1 = strchr(p, ',')) != 0)
			*p1++ = '\0';

		if (*p == 'h')
			ns16550->ns16550_cflag |= CRTSCTS;
		else if (*p == 's')
			ns16550->ns16550_cflag |= CRTSXOFF;
	}
}

/*
 * Check for abort character sequence
 */
static boolean_t
abort_charseq_recognize(uchar_t ch)
{
	static int state = 0;
#define	CNTRL(c) ((c)&037)
	static char sequence[] = { '\r', '~', CNTRL('b') };

	if (ch == sequence[state]) {
		if (++state >= sizeof (sequence)) {
			state = 0;
			return (B_TRUE);
		}
	} else {
		state = (ch == sequence[0]) ? 1 : 0;
	}
	return (B_FALSE);
}

/*
 * Flow control functions
 */
/*
 * Software input flow control
 * This function can execute software input flow control sucessfully
 * at most of situations except that the line is in BREAK status
 * (timed and untimed break).
 * INPUT VALUE of onoff:
 *               FLOW_START means to send out a XON char
 *                          and clear SW input flow control flag.
 *               FLOW_STOP means to send out a XOFF char
 *                          and set SW input flow control flag.
 *               FLOW_CHECK means to check whether there is pending XON/XOFF
 *                          if it is true, send it out.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 * RETURN VALUE: B_FALSE means no flow control char is sent
 *               B_TRUE means one flow control char is sent
 */
static boolean_t
nsasync_flowcontrol_sw_input(struct ns16550com *ns16550, nsasync_flowc_action onoff,
    int type)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int instance = UNIT(nsasync->nsasync_dev);
	int rval = B_FALSE;

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));

	if (!(nsasync->nsasync_ttycommon.t_iflag & IXOFF))
		return (rval);

	/*
	 * If we get this far, then we know IXOFF is set.
	 */
	switch (onoff) {
	case FLOW_STOP:
		nsasync->nsasync_inflow_source |= type;

		/*
		 * We'll send an XOFF character for each of up to
		 * three different input flow control attempts to stop input.
		 * If we already send out one XOFF, but FLOW_STOP comes again,
		 * it seems that input flow control becomes more serious,
		 * then send XOFF again.
		 */
		if (nsasync->nsasync_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			nsasync->nsasync_flags |= NSASYNC_SW_IN_FLOW |
			    NSASYNC_SW_IN_NEEDED;
		DEBUGCONT2(NS16550_DEBUG_SFLOW, "nsasync%d: input sflow stop, "
		    "type = %x\n", instance, nsasync->nsasync_inflow_source);
		break;
	case FLOW_START:
		nsasync->nsasync_inflow_source &= ~type;
		if (nsasync->nsasync_inflow_source == 0) {
			nsasync->nsasync_flags = (nsasync->nsasync_flags &
			    ~NSASYNC_SW_IN_FLOW) | NSASYNC_SW_IN_NEEDED;
			DEBUGCONT1(NS16550_DEBUG_SFLOW, "nsasync%d: "
			    "input sflow start\n", instance);
		}
		break;
	default:
		break;
	}

	if ((nsasync->nsasync_flags & (NSASYNC_SW_IN_NEEDED | NSASYNC_BREAK | NSASYNC_OUT_SUSPEND)) == NSASYNC_SW_IN_NEEDED) {
		/*
		 * If we get this far, then we know we need to send out
		 * XON or XOFF char.
		 */
		nsasync->nsasync_flags = (nsasync->nsasync_flags & ~NSASYNC_SW_IN_NEEDED) | NSASYNC_BUSY;
		while (!ns16550_tx_is_ready(ns16550)) {}
		ns16550_put_char(ns16550, nsasync->nsasync_flags & NSASYNC_SW_IN_FLOW ?  nsasync->nsasync_stopc : nsasync->nsasync_startc);
		rval = B_TRUE;
	}
	return (rval);
}

/*
 * Software output flow control
 * This function can be executed sucessfully at any situation.
 * It does not handle HW, and just change the SW output flow control flag.
 * INPUT VALUE of onoff:
 *                 FLOW_START means to clear SW output flow control flag,
 *			also combine with HW output flow control status to
 *			determine if we need to set NSASYNC_OUT_FLW_RESUME.
 *                 FLOW_STOP means to set SW output flow control flag,
 *			also clear NSASYNC_OUT_FLW_RESUME.
 */
static void
nsasync_flowcontrol_sw_output(struct ns16550com *ns16550, nsasync_flowc_action onoff)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int instance = UNIT(nsasync->nsasync_dev);

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));

	if (!(nsasync->nsasync_ttycommon.t_iflag & IXON))
		return;

	switch (onoff) {
	case FLOW_STOP:
		nsasync->nsasync_flags |= NSASYNC_SW_OUT_FLW;
		nsasync->nsasync_flags &= ~NSASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(NS16550_DEBUG_SFLOW, "nsasync%d: output sflow stop\n",
		    instance);
		break;
	case FLOW_START:
		nsasync->nsasync_flags &= ~NSASYNC_SW_OUT_FLW;
		if (!(nsasync->nsasync_flags & NSASYNC_HW_OUT_FLW))
			nsasync->nsasync_flags |= NSASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(NS16550_DEBUG_SFLOW, "nsasync%d: output sflow start\n",
		    instance);
		break;
	default:
		break;
	}
}

/*
 * Hardware input flow control
 * This function can be executed sucessfully at any situation.
 * It directly changes RTS depending on input parameter onoff.
 * INPUT VALUE of onoff:
 *       FLOW_START means to clear HW input flow control flag,
 *                  and pull up RTS if it is low.
 *       FLOW_STOP means to set HW input flow control flag,
 *                  and low RTS if it is high.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 */
static void
nsasync_flowcontrol_hw_input(struct ns16550com *ns16550, nsasync_flowc_action onoff,
    int type)
{
	uchar_t	mcr;
	uchar_t	flag;
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int instance = UNIT(nsasync->nsasync_dev);

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));

	if (!(nsasync->nsasync_ttycommon.t_cflag & CRTSXOFF))
		return;

	switch (onoff) {
	case FLOW_STOP:
		nsasync->nsasync_inflow_source |= type;
		if (nsasync->nsasync_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			nsasync->nsasync_flags |= NSASYNC_HW_IN_FLOW;
		DEBUGCONT2(NS16550_DEBUG_HFLOW, "nsasync%d: input hflow stop, "
		    "type = %x\n", instance, nsasync->nsasync_inflow_source);
		break;
	case FLOW_START:
		nsasync->nsasync_inflow_source &= ~type;
		if (nsasync->nsasync_inflow_source == 0) {
			nsasync->nsasync_flags &= ~NSASYNC_HW_IN_FLOW;
			DEBUGCONT1(NS16550_DEBUG_HFLOW, "nsasync%d: "
			    "input hflow start\n", instance);
		}
		break;
	default:
		break;
	}
	mcr = ns16550_get_mcr(ns16550);
	flag = (nsasync->nsasync_flags & NSASYNC_HW_IN_FLOW) ? 0 : RTS;

	if (((mcr ^ flag) & RTS) != 0) {
		ns16550_set_mcr(ns16550, (mcr ^ RTS));
	}
}

/*
 * Hardware output flow control
 * This function can execute HW output flow control sucessfully
 * at any situation.
 * It doesn't really change RTS, and just change
 * HW output flow control flag depending on CTS status.
 * INPUT VALUE of onoff:
 *                FLOW_START means to clear HW output flow control flag.
 *			also combine with SW output flow control status to
 *			determine if we need to set NSASYNC_OUT_FLW_RESUME.
 *                FLOW_STOP means to set HW output flow control flag.
 *			also clear NSASYNC_OUT_FLW_RESUME.
 */
static void
nsasync_flowcontrol_hw_output(struct ns16550com *ns16550, nsasync_flowc_action onoff)
{
	struct nsasyncline *nsasync = ns16550->ns16550_priv;
	int instance = UNIT(nsasync->nsasync_dev);

	ASSERT(mutex_owned(&ns16550->ns16550_excl_hi));

	if (!(nsasync->nsasync_ttycommon.t_cflag & CRTSCTS))
		return;

	switch (onoff) {
	case FLOW_STOP:
		nsasync->nsasync_flags |= NSASYNC_HW_OUT_FLW;
		nsasync->nsasync_flags &= ~NSASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(NS16550_DEBUG_HFLOW, "nsasync%d: output hflow stop\n",
		    instance);
		break;
	case FLOW_START:
		nsasync->nsasync_flags &= ~NSASYNC_HW_OUT_FLW;
		if (!(nsasync->nsasync_flags & NSASYNC_SW_OUT_FLW))
			nsasync->nsasync_flags |= NSASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(NS16550_DEBUG_HFLOW, "nsasync%d: output hflow start\n",
		    instance);
		break;
	default:
		break;
	}
}


/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
ns16550quiesce(dev_info_t *devi)
{
	int instance;
	struct ns16550com *ns16550;

	instance = ddi_get_instance(devi);	/* find out which unit */

	ns16550 = ddi_get_soft_state(ns16550_soft_state, instance);
	if (ns16550 == NULL)
		return (DDI_FAILURE);

	/* disable all interrupts */
	ns16550_set_icr(ns16550, 0, RIEN | TIEN);

	/* reset the FIFO */
	ns16550_reset_fifo(ns16550, FIFOTXFLSH | FIFORXFLSH);

	return (DDI_SUCCESS);
}

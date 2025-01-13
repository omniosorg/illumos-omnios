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
 * MMIO UART implementation for Arm PL011 compatible UARTs.
 *
 * The registers are programmed in the same way as EDK2, as driven
 * by the efiserialio driver.
 */
#include "pl011.h"
#include "mmio_uart.h"

#include <bootstrap.h>
#include <stand.h>

#define	IS_GENERIC_UART(__u)	(((__u) != NULL) && \
				((__u)->mu_type == MMIO_UART_TYPE_ARM_GENERIC))

/*
 * Register offsets and definitions taken from DEN0094D (BSA).
 *
 * §B.2 Generic UART register frame
 *
 * Additional register offsets from the PL011 TRM (DDI0183) - these, along
 * with the reason they are elided from the generic UART, are:
 * - UARTILPR_REG: IrDA is unused
 * - UARTIBRD_REG: BAUD selection is unsupported
 * - UARTFBRD_REG: BAUD selection is unsupported
 * - UARTLCR_H_REG: Line Control is unsupported
 * - UARTCR_REG: UART configuration is fixed
 * - UARTIFLS_REG: FIFO configuration is fixed
 * - UARTDMACR_REG: FIFO DMA is unsupported
 * - UARTPeriphID[0-3]: Not documented
 * - UARTPCellID[0-3]: Not documented
 */
#define	UARTDR_REG	0x000	/* Data Register			*/
#define	UARTDR_OE			(1U << 11)
#define	UARTDR_BE			(1U << 10)
#define	UARTDR_PE			(1U << 9)
#define	UARTDR_FE			(1U << 8)
#define	UARTDR_DATA			(0xFFU)
#define	UARTRSR_REG	0x004	/* Receive Status Register		*/
#define	UARTRSR_OE			(1U << 3)
#define	UARTRSR_BE			(1U << 2)
#define	UARTRSR_PE			(1U << 1)
#define	UARTRSR_FE			(1U << 0)
#define	UARTECR_REG	0x004	/* Error Clear Register			*/
#define	UARTECR_CLR			(0xFFU)
#define	UARTFR_REG	0x018	/* Flag Register			*/
#define	UARTFR_RI			(1U << 8)
#define	UARTFR_TXFE			(1U << 7)
#define	UARTFR_RXFF			(1U << 6)
#define	UARTFR_TXFF			(1U << 5)
#define	UARTFR_RXFE			(1U << 4)
#define	UARTFR_BUSY			(1U << 3)
#define	UARTFR_DCD			(1U << 2)
#define	UARTFR_DSR			(1U << 1)
#define	UARTFR_CTS			(1U << 0)
#define	UARTILPR_REG	0x020	/* IrDA Lower-Power Counter Register	*/
#define	UARTIBRD_REG	0x024	/* Integer Baud Rate Register		*/
#define	UARTIBRD_DIVINT			(0xFFFFU)
#define	UARTFBRD_REG	0x028	/* Fractional Baud Rate Register	*/
#define	UARTFBRD_DIVFRAC		(0x3FU)
#define	UARTLCR_H_REG	0x02C	/* Line Control Register		*/
#define	UARTLCR_H_SPS			(1U << 7)
#define	UARTLCR_H_WLEN			(3U << 5)
#define	UARTLCR_H_FEN			(1U << 4)
#define	UARTLCR_H_STP2			(1U << 3)
#define	UARTLCR_H_EPS			(1U << 2)
#define	UARTLCR_H_PEN			(1U << 1)
#define	UARTLCR_H_BRK			(1U << 0)
#define	UARTCR_REG	0x030	/* Control Register			*/
#define	UARTCR_CTSEn			(1U << 15)
#define	UARTCR_RTSEn			(1U << 14)
#define	UARTCR_Out2			(1U << 13)
#define	UARTCR_Out1			(1U << 12)
#define	UARTCR_RTS			(1U << 11)
#define	UARTCR_DTR			(1U << 10)
#define	UARTCR_RXE			(1U << 9)
#define	UARTCR_TXE			(1U << 8)
#define	UARTCR_LBE			(1U << 7)
#define	UARTCR_SIRLP			(1U << 2)
#define	UARTCR_SIREN			(1U << 1)
#define	UARTCR_UARTEN			(1U << 0)
#define	UARTIFLS_REG	0x034	/* Interrupt FIFO Level Select Register	*/
#define	UARTIFLS_RXIFLSEL		(7U << 3)
#define	UARTIFLS_TXIFLSEL		(7U << 0)
#define	UARTIMSC_REG	0x038	/* Interrupt Mask Set/Clear Register	*/
#define	UARTIMSC_OEIM			(1U << 10)
#define	UARTIMSC_BEIM			(1U << 9)
#define	UARTIMSC_PEIM			(1U << 8)
#define	UARTIMSC_FEIM			(1U << 7)
#define	UARTIMSC_RTIM			(1U << 6)
#define	UARTIMSC_TXIM			(1U << 5)
#define	UARTIMSC_RXIM			(1U << 4)
#define	UARTIMSC_DSRMIM			(1U << 3)
#define	UARTIMSC_DCDMIM			(1U << 2)
#define	UARTIMSC_CTSMIM			(1U << 1)
#define	UARTIMSC_RIMIM			(1U << 0)
#define	UARTRIS_REG	0x03c	/* Raw Interrupt Status Register	*/
#define	UARTRIS_OERIS			(1U << 10)
#define	UARTRIS_BERIS			(1U << 9)
#define	UARTRIS_PERIS			(1U << 8)
#define	UARTRIS_FERIS			(1U << 7)
#define	UARTRIS_RTRIS			(1U << 6)
#define	UARTRIS_TXRIS			(1U << 5)
#define	UARTRIS_RXRIS			(1U << 4)
#define	UARTRIS_DSRRMIS			(1U << 3)
#define	UARTRIS_DCDRMIS			(1U << 2)
#define	UARTRIS_CTSRMIS			(1U << 1)
#define	UARTRIS_RIRMIS			(1U << 0)
#define	UARTMIS_REG	0x040	/* Masked Interrupt Status Register	*/
#define	UARTMIS_OEMIS			(1U << 10)
#define	UARTMIS_BEMIS			(1U << 9)
#define	UARTMIS_PEMIS			(1U << 8)
#define	UARTMIS_FEMIS			(1U << 7)
#define	UARTMIS_RTMIS			(1U << 6)
#define	UARTMIS_TXMIS			(1U << 5)
#define	UARTMIS_RXMIS			(1U << 4)
#define	UARTMIS_DSRMMIS			(1U << 3)
#define	UARTMIS_DCDMMIS			(1U << 2)
#define	UARTMIS_CTSMMIS			(1U << 1)
#define	UARTMIS_RIMMIS			(1U << 0)
#define	UARTICR_REG	0x044	/* Interrupt Clear Register		*/
#define	UARTICR_OEIC			(1U << 10)
#define	UARTICR_BEIC			(1U << 9)
#define	UARTICR_PEIC			(1U << 8)
#define	UARTICR_FEIC			(1U << 7)
#define	UARTICR_RTIC			(1U << 6)
#define	UARTICR_TXIC			(1U << 5)
#define	UARTICR_RXIC			(1U << 4)
#define	UARTICR_DSRMIC			(1U << 3)
#define	UARTICR_DCDMIC			(1U << 2)
#define	UARTICR_CTSMIC			(1U << 1)
#define	UARTICR_RIMIC			(1U << 0)
#define	UARTDMACR_REG	0x048	/* DMA Control Register			*/
#define	UARTDMACR_DMAONERR		(1U << 2)
#define	UARTDMACR_TXDMAE		(1U << 1)
#define	UARTDMACR_RXDMAE		(1U << 0)
#define	UARTPeriphID0	0xFE0	/* Peripheral Identification Register 0	*/
#define	UARTPeriphID0_PartNumber0	(0xFFU)
#define	UARTPeriphID1	0xFE4	/* Peripheral Identification Register 1	*/
#define	UARTPeriphID1_Designer0		(0xF0U)
#define	UARTPeriphID1_PartNumber1	(0x0FU)
#define	UARTPeriphID2	0xFE8	/* Peripheral Identification Register 2	*/
#define	UARTPeriphID2_Revision		(0xF0U)
#define	UARTPeriphID2_Designer1		(0x0FU)
#define	UARTPeriphID3	0xFEC	/* Peripheral Identification Register 3	*/
#define	UARTPeriphID3_Configuration	(0xFFU)
#define	UARTPCellID0	0xFF0	/* PrimeCell Identification Register 0	*/
#define	UARTPCellID0_UARTPCellID0	(0x0FU)
#define	UARTPCellID1	0xFF4	/* PrimeCell Identification Register 1	*/
#define	UARTPCellID1_UARTPCellID1	(0x0FU)
#define	UARTPCellID2	0xFF8	/* PrimeCell Identification Register 2	*/
#define	UARTPCellID2_UARTPCellID2	(0x0FU)
#define	UARTPCellID3	0xFFC	/* PrimeCell Identification Register 3	*/
#define	UARTPCellID3_UARTPCellID3	(0x0FU)

typedef struct {
	double		bm_min;
	double		bm_max;
	uint64_t	bm_val;
} pl011_baud_match_t;

/*
 * The maximum error rate is 1.56%, so we allow for 1.57% either side.
 */
#define	BAUDMATCH_FUZZ_LO	0.9843
#define	BAUDMATCH_FUZZ_HI	1.0157

#define	BAUDMATCH_ENTRY(__b)	{		\
	.bm_min = (__b) * (BAUDMATCH_FUZZ_LO),	\
	.bm_max = (__b) * (BAUDMATCH_FUZZ_HI),	\
	.bm_val = (__b)				\
}

static const pl011_baud_match_t pl011_baud_matchers[] = {
	BAUDMATCH_ENTRY(UINT64_C(115200)),
	BAUDMATCH_ENTRY(UINT64_C(57600)),
	BAUDMATCH_ENTRY(UINT64_C(19200)),
	BAUDMATCH_ENTRY(UINT64_C(9600)),
	BAUDMATCH_ENTRY(UINT64_C(50)),
	BAUDMATCH_ENTRY(UINT64_C(75)),
	BAUDMATCH_ENTRY(UINT64_C(110)),
	BAUDMATCH_ENTRY(UINT64_C(134)),
	BAUDMATCH_ENTRY(UINT64_C(150)),
	BAUDMATCH_ENTRY(UINT64_C(200)),
	BAUDMATCH_ENTRY(UINT64_C(300)),
	BAUDMATCH_ENTRY(UINT64_C(600)),
	BAUDMATCH_ENTRY(UINT64_C(1200)),
	BAUDMATCH_ENTRY(UINT64_C(1800)),
	BAUDMATCH_ENTRY(UINT64_C(2400)),
	BAUDMATCH_ENTRY(UINT64_C(4800)),
	BAUDMATCH_ENTRY(UINT64_C(38400)),
	BAUDMATCH_ENTRY(UINT64_C(76800)),
	BAUDMATCH_ENTRY(UINT64_C(153600)),
	BAUDMATCH_ENTRY(UINT64_C(230400)),
	BAUDMATCH_ENTRY(UINT64_C(307200)),
	BAUDMATCH_ENTRY(UINT64_C(460800)),
	BAUDMATCH_ENTRY(UINT64_C(921600)),
	BAUDMATCH_ENTRY(UINT64_C(1000000)),
	BAUDMATCH_ENTRY(UINT64_C(1152000)),
	BAUDMATCH_ENTRY(UINT64_C(1500000)),
	BAUDMATCH_ENTRY(UINT64_C(2000000)),
	BAUDMATCH_ENTRY(UINT64_C(2500000)),
	BAUDMATCH_ENTRY(UINT64_C(3000000)),
	BAUDMATCH_ENTRY(UINT64_C(3500000)),
	BAUDMATCH_ENTRY(UINT64_C(4000000)),
};
static const size_t num_pl011_baud_matchers =
    sizeof (pl011_baud_matchers) / sizeof (pl011_baud_matchers[0]);

static uint64_t
pl011_match_baud(const double baud)
{
	size_t n;

	for (n = 0; n < num_pl011_baud_matchers; ++n) {
		if (pl011_baud_matchers[n].bm_min <= baud &&
		    pl011_baud_matchers[n].bm_max >= baud) {
			return (pl011_baud_matchers[n].bm_val);
		}
	}

	return (0);
}

static uint16_t
pl011_read16(pl011_info_t *pl011, uint16_t reg)
{
	return (*(volatile uint16_t *)(pl011->pl_addr + reg));
}

static void
pl011_write16(pl011_info_t *pl011, uint16_t reg, uint16_t val)
{
	(*(volatile uint16_t *)(pl011->pl_addr + reg)) = val;
}

static uint8_t
pl011_read8(pl011_info_t *pl011, uint16_t reg)
{
	return (*(volatile uint8_t *)(pl011->pl_addr + reg));
}

static void
pl011_write8(pl011_info_t *pl011, uint16_t reg, uint8_t val)
{
	(*(volatile uint8_t *)(pl011->pl_addr + reg)) = val;
}

static bool
pl011_setup(void *ctx)
{
	uint16_t		tmp_cr;
	uint16_t		ibrd = 0;
	uint8_t			fbrd = 0;
	uint8_t			lcr = 0;
	uint16_t		cr = 0;
	mmio_uart_t		*uart = ctx;
	pl011_info_t		*pl011 = uart->mu_ctx;

	if (IS_GENERIC_UART(uart)) {
		/*
		 * There's no way to change the speed (or any other meaningful
		 * settings) for the generic UART, so we just bail.
		 */
		return (true);
	}

	cr = pl011->pl_cr = pl011_read16(pl011, UARTCR_REG);
	lcr = pl011->pl_lcr = pl011_read8(pl011, UARTLCR_H_REG);
	ibrd = pl011->pl_ibrd = pl011_read16(pl011, UARTIBRD_REG);
	fbrd = pl011->pl_fbrd = pl011_read8(pl011, UARTFBRD_REG);

	/*
	 * If we have both a clock frequency and a desired speed we can
	 * calculate our required IBRD and FBRD. If we can't we just use
	 * the current values.
	 */
	if (pl011->pl_frequency != 0 && uart->mu_speed != 0) {
		uint64_t	denominator;
		uint64_t	divisor;
		uint64_t	remainder;

		/*
		 * This ingenious way of working out the integer and
		 * fractional values is from NetBSD.
		 */
		denominator = 16 * uart->mu_speed;
		divisor = pl011->pl_frequency / denominator;
		remainder = pl011->pl_frequency % denominator;

		ibrd = divisor << 6;
		fbrd = (((8 * remainder) / uart->mu_speed) + 1) / 2;

		/*
		 * - The minimum divide ratio possible is 1 and the maximum is
		 *   65535(216 - 1). That is, UARTIBRD = 0 is invalid and
		 *   UARTFBRD is ignored when this is the case.
		 * - Similarly, when UARTIBRD = 65535 (that is 0xFFFF), then
		 *   UARTFBRD must not be greater than zero. If this is
		 *   exceeded it results in an aborted transmission or
		 *   reception.
		 */
		if (ibrd == 0) {
			ibrd = 1;
			fbrd = 0;
		} else if (ibrd == 0xFFFF) {
			fbrd = 0;
		}
	}

	lcr &= ~(UARTLCR_H_WLEN);
	switch (uart->mu_data_bits) {
	case MMIO_UART_DATA_BITS_8:
		lcr |= 0x60;
		break;
	case MMIO_UART_DATA_BITS_7:
		lcr |= 0x40;
		break;
	case MMIO_UART_DATA_BITS_6:
		lcr |= 0x20;
		break;
	case MMIO_UART_DATA_BITS_5:
		/* nothing to set, bits 6:5 are b00 */
		break;
	default:
		return (false);
	}

	lcr &= ~(UARTLCR_H_PEN|UARTLCR_H_EPS|UARTLCR_H_SPS);
	switch (uart->mu_parity) {
	case MMIO_UART_PARITY_SPACE:
		lcr |= (UARTLCR_H_PEN|UARTLCR_H_EPS|UARTLCR_H_SPS);
		break;
	case MMIO_UART_PARITY_MARK:
		lcr |= (UARTLCR_H_PEN|UARTLCR_H_SPS);
		break;
	case MMIO_UART_PARITY_NONE:
		/* i.e. do not set UARTLCR_H_PEN */
		break;
	case MMIO_UART_PARITY_EVEN:
		lcr |= (UARTLCR_H_PEN|UARTLCR_H_EPS);
		break;
	case MMIO_UART_PARITY_ODD:
		lcr |= (UARTLCR_H_PEN);
		break;
	default:
		return (false);
	}

	lcr &= ~(UARTLCR_H_STP2);
	switch (uart->mu_stop_bits) {
	case MMIO_UART_STOP_BITS_1:
		/* i.e. do not set UARTLCR_H_STP2 */
		break;
	case MMIO_UART_STOP_BITS_2:
		lcr |= UARTLCR_H_STP2;
		break;
	default:
		return (false);
	}

	/*
	 * We only touch the FIFO-enable bit if we're not the stdout.
	 *
	 * This seems weird, but the idea is that UEFI will set them
	 * how it likes and we want to avoid changing what it thinks
	 * is the ground truth.
	 */
	if (!(uart->mu_flags & MMIO_UART_STDOUT)) {
		lcr |= UARTLCR_H_FEN;
	}

	if (uart->mu_rtsdtr_off) {
		cr &= ~(UARTCR_RTS|UARTCR_DTR);
	} else {
		cr |= UARTCR_RTS;	/* DTR? this is what efiserialio does */
	}

	cr |= (UARTCR_RXE|UARTCR_TXE|UARTCR_UARTEN);

	if (ibrd == pl011->pl_ibrd && fbrd == pl011->pl_fbrd &&
	    lcr == pl011->pl_lcr && cr == pl011->pl_cr)
		return (true);

	/*
	 * If enabled we must disable and drain before reprogramming
	 */
	if ((tmp_cr = pl011_read16(pl011, UARTCR_REG)) & UARTCR_UARTEN) {
		if ((tmp_cr & UARTCR_TXE) && (tmp_cr & UARTCR_UARTEN)) {
			while (!(pl011_read16(pl011, UARTFR_REG) & UARTFR_TXFE))
				/* drain the TX FIFO */;
			/* disable the UART */
			pl011_write16(pl011, UARTCR_REG,
			    tmp_cr & ~(UARTCR_UARTEN));
			while (pl011_read16(pl011, UARTFR_REG) & UARTFR_BUSY)
				/* drain the output buffer */;
		} else {
			/* disable the UART */
			pl011_write16(pl011, UARTCR_REG,
			    tmp_cr & ~(UARTCR_UARTEN));
		}
	}

	/* clear errors */
	pl011_write8(pl011, UARTECR_REG, 0xF);

	/*
	 * IBRD, FBRD and LCR_H form a single logical 30bit register which
	 * is strobed when LCR_H is written.
	 */
	if (ibrd != 0 && ibrd != pl011->pl_ibrd) {
		pl011_write16(pl011, UARTIBRD_REG, ibrd);
		pl011->pl_ibrd = ibrd;
	}

	if (fbrd != 0 && fbrd != pl011->pl_fbrd) {
		pl011_write8(pl011, UARTFBRD_REG, fbrd);
		pl011->pl_fbrd = fbrd;
	}

	if ((ibrd != 0 && ibrd != pl011->pl_ibrd) ||
	    (fbrd != 0 && fbrd != pl011->pl_fbrd) ||
	    lcr != pl011->pl_lcr) {
		pl011_write8(pl011, UARTLCR_H_REG, lcr);
		pl011->pl_lcr = lcr;
	}

	/*
	 * Our calculated CR also re-enables the UART.
	 */
	pl011_write16(pl011, UARTCR_REG, cr);
	pl011->pl_cr = cr;

	return (true);
}

static bool
pl011_config_check(void *ctx, mmio_uart_speed_t speed,
    mmio_uart_data_bits_t dbits, mmio_uart_parity_t parity,
    mmio_uart_stop_bits_t sbits)
{
	/*
	 * PL011 does not support 1.5 stop bits.
	 */
	if (sbits == MMIO_UART_STOP_BITS_1_5)
		return (false);

	return (true);
}

static bool
pl011_has_carrier(void *ctx)
{
	mmio_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->mu_ctx;

	return ((pl011_read16(pl011, UARTFR_REG) & UARTFR_DCD) ? true : false);
}

static void
pl011_putchar(void *ctx, int c)
{
	mmio_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->mu_ctx;

	while (pl011_read16(pl011, UARTFR_REG) & UARTFR_TXFF)
		/* just polling... */;
	pl011_write8(pl011, UARTDR_REG, (uint8_t)(c & 0xFF));
}

static int
pl011_ischar(void *ctx)
{
	mmio_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->mu_ctx;

	if (pl011_read16(pl011, UARTFR_REG) & UARTFR_RXFE)
		return (0);

	return (1);
}

static int
pl011_getchar(void *ctx)
{
	mmio_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->mu_ctx;

	if (pl011_ischar(ctx) == 0)
		return (-1);

	return ((int)pl011_read8(pl011, UARTDR_REG));
}

static int
pl011_getspeed(void *ctx)
{
	mmio_uart_t	*uart = ctx;
	return (uart->mu_speed);
}

static void
pl011_devinfo(void *ctx)
{
	mmio_uart_t	*uart = ctx;
	pl011_info_t	*pl011 = uart->mu_ctx;

	printf("\tmmio %#lx", pl011->pl_addr);
}

static int
pl011_make_tty_hook(void *ctx)
{
	mmio_uart_speed_t	speed;
	mmio_uart_data_bits_t	data_bits;
	mmio_uart_parity_t	parity;
	mmio_uart_stop_bits_t	stop_bits;
	bool			ignore_cd;
	bool			rtsdtr_off;
	mmio_uart_t		*uart = ctx;
	pl011_info_t		*pl011 = uart->mu_ctx;

	if (pl011->pl_addr == 0 || pl011->pl_addr_len == 0)
		return (-1);

	/* ensure that all interrupts are masked and cleared */
	if ((pl011_read16(pl011, UARTIMSC_REG) & 0x7FF) != 0x7FF) {
		pl011_write16(pl011, UARTIMSC_REG, 0x7FF);
		pl011_write16(pl011, UARTICR_REG, 0x7FF);
	}

	if (IS_GENERIC_UART(uart)) {
		/*
		 * Set up per DEN0094D §B.4 (Control and setup)
		 *
		 * There's not much we can do with a generic UART other
		 * than simply use it.
		 */
		pl011->pl_lcr = 0x60|UARTLCR_H_FEN;
		pl011->pl_cr = UARTCR_RXE|UARTCR_TXE|UARTCR_UARTEN;
		pl011->pl_ibrd = 0;
		pl011->pl_fbrd = 0;

		uart->mu_data_bits = MMIO_UART_DATA_BITS_8;
		uart->mu_parity = MMIO_UART_PARITY_NONE;
		uart->mu_stop_bits = MMIO_UART_STOP_BITS_1;
		uart->mu_ignore_cd = true;
		uart->mu_rtsdtr_off = true;

		/*
		 * Speed is configured in FDT or SPCR for a generic UART,
		 * so leave setting this to the discovery code in the happy
		 * path, but if that has not set anything reasonable, set
		 * our default.
		 */
		if (uart->mu_speed == 0)
			uart->mu_speed = MMIO_UART_DEFAULT_COMSPEED;

		return (0);
	}

	pl011->pl_cr = pl011_read16(pl011, UARTCR_REG);
	pl011->pl_lcr = pl011_read8(pl011, UARTLCR_H_REG);
	pl011->pl_ibrd = pl011_read16(pl011, UARTIBRD_REG);
	pl011->pl_fbrd = pl011_read8(pl011, UARTFBRD_REG);

	/*
	 * We can only determine the BAUD rate if we know the clock frequency.
	 */
	speed = uart->mu_speed;
	if (pl011->pl_frequency != 0) {
		/*
		 * If we have the frequency we can read the current speed from
		 * the integer and fractional BAUD register values.
		 *
		 * Given a 6bit UARTFBRD the maximum error rate is 1.56%,
		 * which we account for in `pl011_match_baud'.
		 */
		uint64_t baud;

		speed = 0;
		if (pl011->pl_ibrd != 0) {
			baud = (pl011->pl_frequency /
			    ((((uint32_t)pl011->pl_ibrd) << 6) +
			    pl011->pl_fbrd)) << 2;
			speed = pl011_match_baud(baud);
		}

		if (speed == 0)
			speed = uart->mu_speed;
	}

	switch (pl011->pl_lcr & UARTLCR_H_WLEN) {
	case 0x60:
		data_bits = MMIO_UART_DATA_BITS_8;
		break;
	case 0x40:
		data_bits = MMIO_UART_DATA_BITS_7;
		break;
	case 0x20:
		data_bits = MMIO_UART_DATA_BITS_6;
		break;
	case 0x00:	/* fallthrough */
	default:
		data_bits = MMIO_UART_DATA_BITS_5;
		break;
	}

	if (pl011->pl_lcr & UARTLCR_H_PEN) {
		if (pl011->pl_lcr & UARTLCR_H_EPS) {
			if (pl011->pl_lcr & UARTLCR_H_SPS) {
				parity = MMIO_UART_PARITY_SPACE;
			} else {
				parity = MMIO_UART_PARITY_EVEN;
			}
		} else {
			if (pl011->pl_lcr & UARTLCR_H_SPS) {
				parity = MMIO_UART_PARITY_MARK;
			} else {
				parity = MMIO_UART_PARITY_ODD;
			}
		}

	} else {
		parity = MMIO_UART_PARITY_NONE;
	}

	if (pl011->pl_lcr & UARTLCR_H_STP2) {
		stop_bits = MMIO_UART_STOP_BITS_2;
	} else {
		stop_bits = MMIO_UART_STOP_BITS_1;
	}

	/*
	 * Ignoring carrier detect is a purely software function, done by
	 * checking the DCD bit in the UARTLCR register. We can't divine an
	 * intention here, so just set a default.
	 */
	ignore_cd = true;

	if ((pl011->pl_cr & (UARTCR_RTS|UARTCR_DTR)) ==
	    (UARTCR_RTS|UARTCR_DTR)) {
		rtsdtr_off = false;
	} else {
		rtsdtr_off = true;
	}

	/*
	 * Update the configuration to match the hardware when required.
	 */
	if (uart->mu_flags & MMIO_UART_CONFIG_FROM_HW) {
		if (speed != 0 || uart->mu_speed == 0)
			uart->mu_speed = speed;
		if (uart->mu_speed == 0)
			uart->mu_speed = MMIO_UART_DEFAULT_COMSPEED;
		uart->mu_data_bits = data_bits;
		uart->mu_parity = parity;
		uart->mu_stop_bits = stop_bits;
		uart->mu_ignore_cd = ignore_cd;
		uart->mu_rtsdtr_off = rtsdtr_off;
	}

	return (0);
}

static int
pl011_no_set(struct env_var *ev __attribute((unused)),
    int flags __attribute((unused)), const void *value __attribute((unused)))
{
	return (CMD_OK);
}

static void
pl011_set_environment(void *ctx)
{
	char		name[50];
	char		value[30];
	struct console	*cp = ctx;
	mmio_uart_t	*uart = cp->c_private;
	pl011_info_t	*pl011 = uart->mu_ctx;

	snprintf(name, sizeof (name), "%s-mmio-base", cp->c_name);
	snprintf(value, sizeof (value), "0x%llx",
	    (unsigned long long)pl011->pl_addr);
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, pl011_no_set, env_nounset);

	snprintf(name, sizeof (name), "%s-mmio-size", cp->c_name);
	snprintf(value, sizeof (value), "0x%llx",
	    (unsigned long long)pl011->pl_addr_len);
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, pl011_no_set, env_nounset);

	snprintf(name, sizeof (name), "%s-clock-frequency", cp->c_name);
	snprintf(value, sizeof (value), "%llu",
	    (unsigned long long)pl011->pl_frequency);
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, pl011_no_set, env_nounset);
}

const mmio_uart_ops_t mmio_uart_pl011_ops = {
	.op_setup		= pl011_setup,
	.op_config_check	= pl011_config_check,
	.op_has_carrier		= pl011_has_carrier,
	.op_putchar		= pl011_putchar,
	.op_getchar		= pl011_getchar,
	.op_ischar		= pl011_ischar,
	.op_getspeed		= pl011_getspeed,
	.op_devinfo		= pl011_devinfo,
	.op_make_tty_hook	= pl011_make_tty_hook,
	.op_set_environment	= pl011_set_environment,
};

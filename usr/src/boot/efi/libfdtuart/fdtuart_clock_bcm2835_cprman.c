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
 * Clock reading support for the firmware clocks on bcm2835 and bcm2711.
 *
 * In our world, this covers the Raspberry Pi4.
 *
 * Basic operation of the mailbox properties interface requires some board
 * knowledge, which is conveniently wrapped up in FDT.
 *
 * The approach is that you build a message with the overall space being
 * sufficient for both the request and the response. This message must live
 * in physical memory completely below the 4GiB mark and the lower 4 bits must
 * be clear.
 *
 * You then call the mailbox, passing the bus-visible address of the message
 * (obtained via dma-ranges) in the upper 28 bits of a 32 bit register write
 * and a channel identifier, which is 4 bits in length and passed in the
 * lower 4 bits of the register write.
 *
 * You then poll the mailbox for data availability and, when data is available,
 * read a value corresponding to the one written above. This (still) contains
 * a bus-visible address and channel, which will match the request.
 *
 * Once you have the response you can check that the addresses match and
 * channel matches, then interpret the data per your structure. In the message
 * header you should check the message code for success, then check your other
 * fields apppropriately. In each returned tag you must check the top bit of
 * the value length field, which on response is set if the tag was processed
 * successfully and clear if it was not. This bit then needs to be masked out
 * when reasoning about the value length.
 *
 * The message header/tag/message breakdown here is a little over-engineered,
 * but makes it easier to follow what's going on and gives a hint as to how
 * to extend the use of the mailbox property interface.
 *
 * See this wiki page for information on the messages:
 *  https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 *
 * Aside from the above page, all of this is woefully underdocumented.
 *
 * It is possible to interface to the cprman clocks via registers instead of
 * the mailbox, but that requires understanding the currently configured
 * clock hierarchy. While possible, this would be significantly more complex.
 */

#include <libfdt.h>

#include "fdtuart.h"
#include "mmio_uart.h"

#define	MBOX_RETRIES			10000000
#define	MBOX_RESPONSE_RETRIES		(10 * (MBOX_RETRIES))

#define	MBOX0_RW_REG			0x00000000	/* VC response to ARM */
#define	MBOX0_STATUS_REG		0x00000018
#define	MBOX_STATUS_FULL		0x80000000
#define	MBOX_STATUS_EMPTY		0x40000000
#define	MBOX1_RW_REG			0x00000020	/* ARM request to VC */
#define	MBOX1_STATUS_REG		0x00000038	/* same bits as MBOX0 */

#define	MBOX_REQUEST_PROCESS		0x00000000
#define	MBOX_RESPONSE_SUCCESS		0x80000000

#define	MBOX_REQUEST_CODE		0x00000000
#define	MBOX_RESPONSE_CODE		0x80000000

#define	MBOX_TAG_END			0x00000000
#define	MBOX_TAG_GETCLKRATE		0x00030002

#define	BCM2835_CLOCK_UART		19		/* cprman clkid */
#define	MBOX_CLOCK_UART			0x00000002	/* mbox clkid */

#define	MBOX_PROP_CHAN_ARM_TO_VC	8

/*
 * Common message header.
 */
typedef struct {
	uint32_t					buffer_size;
	uint32_t					code;
} bcm2835_mbox_msg_header_t;

/*
 * Common tag header.
 */
typedef struct {
	uint32_t					tag;
	uint32_t					value_buffer_size;
	uint32_t					value_length;
} bcm2835_mbox_tag_header_t;

/*
 * Get Clock Rate request.
 */
typedef struct {
	uint32_t					clock_id;
} bcm2835_mbox_get_clock_rate_req_t;

/*
 * Get Clock Rate response.
 */
typedef struct {
	uint32_t					clock_id;
	uint32_t					rate;
} bcm2835_mbox_get_clock_rate_rsp_t;

/*
 * Full Get Clock Rate message.
 *
 * Note that there is no padding in this structure. It is effectively an array
 * of eight uint32_t values (32 bytes).
 */
typedef struct {
	bcm2835_mbox_msg_header_t			mhdr;
	bcm2835_mbox_tag_header_t			thdr;
	union {
		bcm2835_mbox_get_clock_rate_req_t	req;
		bcm2835_mbox_get_clock_rate_rsp_t	rsp;
	}						payload;
	uint32_t					end_tag;
} bcm2835_mbox_get_clock_rate_t;

/*
 * Helper macro to correctly initialise a Get Clock Rate message.
 */
#define	CREATE_GET_CLOCK_RATE_MSG(__msg, __clkid)	do {	\
	uint32_t *__arr = (uint32_t *)(__msg);			\
	size_t __i;						\
	for (__i = 0;						\
	    __i < (sizeof (*(__msg)) / sizeof (uint32_t));	\
	    ++__i)						\
		__arr[__i] = (MBOX_TAG_END);			\
	(__msg)->mhdr.buffer_size = sizeof (*(__msg));		\
	(__msg)->mhdr.code = (MBOX_REQUEST_PROCESS);		\
	(__msg)->thdr.tag = MBOX_TAG_GETCLKRATE;		\
	(__msg)->thdr.value_buffer_size =			\
	    sizeof ((__msg)->payload);				\
	(__msg)->thdr.value_length = MBOX_REQUEST_CODE |	\
	    sizeof ((__msg)->payload.req);			\
	(__msg)->payload.req.clock_id = (__clkid);		\
} while (0)

extern void cpu_flush_dcache(const void *, size_t);
extern void cpu_invalidate_dcache(const void *, size_t);

static uint32_t
fdtuart_bcm2835_mbox_readreg(void *base, uint16_t reg)
{
	return (*((volatile uint32_t *)(((char *)base) + reg)));
}

static void
fdtuart_bcm2835_mbox_writereg(void *base, uint16_t reg, uint32_t val)
{
	*((volatile uint32_t *)(((char *)base) + reg)) = val;
}

static int
fdtuart_bcm2835_mbox_call(uint32_t *base,
    uint8_t chan, uint32_t saddr, uint32_t *raddr)
{
	uint64_t ctr;
	uint32_t rdval;

	if (saddr & 0xf)
		return (-1);

	if (chan & 0xf0)
		return (-1);

	/*
	 * Wait for both the output and input channels to be drained
	 */

	/* drain stale output */
	for (ctr = 0; ctr < MBOX_RETRIES; ++ctr) {
		if (fdtuart_bcm2835_mbox_readreg(base,
		    MBOX0_STATUS_REG) & MBOX_STATUS_EMPTY)
			break;
		fdtuart_bcm2835_mbox_readreg(base, MBOX0_RW_REG);
	}

	if (ctr >= MBOX_RETRIES)
		return (-1);

	/* while unprocessed input exists, drain output */
	for (ctr = 0; ctr < MBOX_RETRIES; ++ctr) {
		if (fdtuart_bcm2835_mbox_readreg(base,
		    MBOX1_STATUS_REG) & MBOX_STATUS_EMPTY)
			break;
		if (fdtuart_bcm2835_mbox_readreg(base,
		    MBOX0_STATUS_REG) & MBOX_STATUS_EMPTY)
			continue;
		fdtuart_bcm2835_mbox_readreg(base, MBOX0_RW_REG);
	}

	if (ctr >= MBOX_RETRIES)
		return (-1);

	/* drain remaining stale output */
	for (ctr = 0; ctr < MBOX_RETRIES; ++ctr) {
		if (fdtuart_bcm2835_mbox_readreg(base,
		    MBOX0_STATUS_REG) & MBOX_STATUS_EMPTY)
			break;
		fdtuart_bcm2835_mbox_readreg(base, MBOX0_RW_REG);
	}

	if (ctr >= MBOX_RETRIES)
		return (-1);

	/*
	 * Everything is fully drained, we can send and receive now.
	 */

	/* send */
	fdtuart_bcm2835_mbox_writereg(base, MBOX1_RW_REG, saddr|chan);

	/* await the response */
	for (ctr = 0; ctr < MBOX_RESPONSE_RETRIES; ++ctr) {
		if (!(fdtuart_bcm2835_mbox_readreg(base,
		    MBOX0_STATUS_REG) & MBOX_STATUS_EMPTY))
			break;
	}

	if (ctr >= MBOX_RESPONSE_RETRIES)
		return (-1);

	/* read the response */
	rdval = fdtuart_bcm2835_mbox_readreg(base, MBOX0_RW_REG);

	/* check for matching channels */
	if ((rdval & 0xf) != chan)
		return (-1);

	/* clear the channel from the response, leaving the bus address */
	*raddr = (rdval & 0xFFFFFFF0);
	return (0);
}

static int
fdtuart_bcm2835_mbox_prop_call(const void *fdtp, int nodeoff,
    uint32_t *base, uint8_t chan, bcm2835_mbox_msg_header_t *msg)
{
	uint64_t t;
	uint32_t saddr;
	uint32_t sbaddr;
	uint32_t raddr;
	uint32_t rbaddr;

	/*
	 * Ensure the the passed message has a physical address in the
	 * lower 4GiB and that it is appropriately aligned.
	 */

	if ((((uint64_t)msg) & 0xFFFFFFF0) != ((uint64_t)msg))
		return (-1);

	/*
	 * Stash the 32bit message physical address and derive a 32bit
	 * message bus address from it.
	 */

	saddr = (uint32_t)((uint64_t)msg);
	t = (uint64_t)saddr;
	if (!fdtuart_phys_to_bus(fdtp, nodeoff, &t, 0x1000))
		return (-1);

	if ((t & 0xFFFFFFF0) != t)
		return (-1);

	sbaddr = (uint32_t)t;

	/*
	 * Call the mailbox interface, ensuring that the cache remains coherent
	 */

	t = msg->buffer_size;
	cpu_flush_dcache(msg, t);

	if (fdtuart_bcm2835_mbox_call(base, chan, sbaddr, &rbaddr) != 0)
		return (-1);

	cpu_invalidate_dcache(msg, t);

	/*
	 * Transform the received message bus address to a physical address,
	 * which must be the same address as the send address and therefore
	 * must also live under 4GiB and be appropriately aligned.
	 */

	t = (uint64_t)rbaddr;
	if (!fdtuart_bus_to_phys(fdtp, nodeoff, &t, 0x1000))
		return (-1);

	if ((t & 0xFFFFFFF0) != t)
		return (-1);

	raddr = (uint32_t)t;

	if (raddr != saddr)
		return (-1);

	/*
	 * Check the overall call result. Note that we expect all tags to
	 * have been processed, so we don't accept partial results.
	 */

	if (msg->code != MBOX_RESPONSE_SUCCESS)
		return (-1);

	return (0);
}

static uint64_t
fdtuart_bcm2835_mbox_get_clock_rate(const void *fdtp, int nodeoff,
    uint32_t *base, uint32_t *msg_mem, uint32_t clkid)
{
	bcm2835_mbox_get_clock_rate_t	*msg =
	    (bcm2835_mbox_get_clock_rate_t *)msg_mem;

	CREATE_GET_CLOCK_RATE_MSG(msg, clkid);

	if (fdtuart_bcm2835_mbox_prop_call(fdtp, nodeoff, base,
	    MBOX_PROP_CHAN_ARM_TO_VC, &msg->mhdr) != 0)
		return (0);

	if (msg->thdr.tag != MBOX_TAG_GETCLKRATE)
		return (0);

	if (msg->thdr.value_buffer_size < sizeof (msg->payload.rsp))
		return (0);

	if (!(msg->thdr.value_length & MBOX_RESPONSE_CODE))
		return (0);

	if ((msg->thdr.value_length & (~(MBOX_RESPONSE_CODE))) !=
	    sizeof (msg->payload.rsp))
		return (0);

	if (msg->payload.rsp.clock_id != clkid)
		return (0);

	return (msg->payload.rsp.rate);
}

uint64_t
fdtuart_bcm2835_cprman_get_clock_rate(const void *fdtp,
    int clkoff, const uint32_t *spec)
{
	uint32_t *msg;
	uint64_t reg;
	uint64_t reg_size;
	uint64_t rate;
	uint32_t clkid;

	/*
	 * Double-check that the bindings have been followed and we
	 * have #clock-cells set to 1.
	 */
	if (fdtuart_get_clock_cells(fdtp, clkoff) != 1)
		return (0);

	/*
	 * We only need to understand the UART clock.
	 */
	switch (fdt32_to_cpu(spec[0])) {
	case BCM2835_CLOCK_UART:
		clkid = MBOX_CLOCK_UART;
		break;
	default:
		return (0);
	}

	/*
	 * We have a valid brcm,bcm2835-cprman node.
	 *
	 * Look up the firmware propery on that node, which contains a
	 * phandle to a raspberrypi,bcm2835-firmware node.
	 */

	if ((clkoff = fdtuart_phandle_from_prop(
	    fdtp, clkoff, "firmware")) < 0)
		return (0);

	if (fdt_node_check_compatible(fdtp, clkoff,
	    "raspberrypi,bcm2835-firmware") != 0)
		return (0);

	/*
	 * On the raspberrypi,bcm2835-firmware node we look up the mboxes
	 * property, which contains a phandle to a brcm,bcm2835-mbox node,
	 * which is the mailbox interface we need to use to resolve the clock.
	 */

	if ((clkoff = fdtuart_phandle_from_prop(fdtp, clkoff, "mboxes")) < 0)
		return (0);

	if (fdt_node_check_compatible(fdtp, clkoff, "brcm,bcm2835-mbox") != 0)
		return (0);

	/*
	 * We now have the offset of the brcm,bcm2835-mbox node in clkoff.
	 * Fetch the resolved registers from this node for use in interfacing
	 * to the mailbox.
	 */

	if (!fdtuart_resolve_reg(fdtp, clkoff, 0, &reg, &reg_size))
		return (0);

	/*
	 * The mailbox interface uses 32bit addressing, so allocate the
	 * mailbox message from low memory. Since we allocate a page we
	 * can be sure we adhere to mailbox alignment requirements.
	 */

	if ((msg = mmio_uart_alloc_low_page()) == NULL)
		return (0);

	/*
	 * Finally, call the mailbox then clean up and return.
	 */
	rate = fdtuart_bcm2835_mbox_get_clock_rate(fdtp, clkoff,
	    (uint32_t *)reg, msg, clkid);

	mmio_uart_free_low_page(msg);
	return (rate);
}

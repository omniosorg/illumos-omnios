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

/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2022 Michael van der Westhuizen
 */

#ifndef _ASM_ATOMIC_H
#define	_ASM_ATOMIC_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern __GNU_INLINE void
atomic_inc_8(volatile uint8_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_uchar(volatile uchar_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_16(volatile uint16_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_ushort(volatile ushort_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_32(volatile uint32_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_uint(volatile uint_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_ulong(volatile ulong_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_inc_64(volatile uint64_t *target)
{
	(void) __sync_add_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_8(volatile uint8_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_uchar(volatile uchar_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_16(volatile uint16_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_ushort(volatile ushort_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_32(volatile uint32_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_uint(volatile uint_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_ulong(volatile ulong_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_dec_64(volatile uint64_t *target)
{
	(void) __sync_sub_and_fetch(target, 1);
}

extern __GNU_INLINE void
atomic_add_8(volatile uint8_t *target, int8_t value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_char(volatile uchar_t *target, signed char value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_16(volatile uint16_t *target, int16_t value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_ushort(volatile ushort_t *target, short value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_32(volatile uint32_t *target, int32_t value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_int(volatile uint32_t *target, int32_t value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_ptr(volatile void *target, ssize_t value)
{
	(void) __sync_add_and_fetch((caddr_t *)target, value);
}

extern __GNU_INLINE void
atomic_add_long(volatile ulong_t *target, long value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_add_64(volatile uint64_t *target, int64_t value)
{
	(void) __sync_add_and_fetch(target, value);
}

extern __GNU_INLINE void
atomic_or_8(volatile uint8_t *target, uint8_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_uchar(volatile uchar_t *target, uchar_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_16(volatile uint16_t *target, uint16_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_ushort(volatile ushort_t *target, ushort_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_32(volatile uint32_t *target, uint32_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_uint(volatile uint_t *target, uint_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_ulong(volatile ulong_t *target, ulong_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_or_64(volatile uint64_t *target, uint64_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_8(volatile uint8_t *target, uint8_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_uchar(volatile uchar_t *target, uchar_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_16(volatile uint16_t *target, uint16_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_ushort(volatile ushort_t *target, ushort_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_32(volatile uint32_t *target, uint32_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_uint(volatile uint_t *target, uint_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_ulong(volatile ulong_t *target, ulong_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_64(volatile uint64_t *target, uint64_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}

extern __GNU_INLINE uint8_t
atomic_inc_8_nv(volatile uint8_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uchar_t
atomic_inc_uchar_nv(volatile uchar_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uint16_t
atomic_inc_16_nv(volatile uint16_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE ushort_t
atomic_inc_ushort_nv(volatile ushort_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uint32_t
atomic_inc_32_nv(volatile uint32_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uint_t
atomic_inc_uint_nv(volatile uint_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE ulong_t
atomic_inc_ulong_nv(volatile ulong_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uint64_t
atomic_inc_64_nv(volatile uint64_t *target)
{
	return (__sync_add_and_fetch(target, 1));
}

extern __GNU_INLINE uint8_t
atomic_dec_8_nv(volatile uint8_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uchar_t
atomic_dec_uchar_nv(volatile uchar_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uint16_t
atomic_dec_16_nv(volatile uint16_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE ushort_t
atomic_dec_ushort_nv(volatile ushort_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uint32_t
atomic_dec_32_nv(volatile uint32_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uint_t
atomic_dec_uint_nv(volatile uint_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE ulong_t
atomic_dec_ulong_nv(volatile ulong_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uint64_t
atomic_dec_64_nv(volatile uint64_t *target)
{
	return (__sync_sub_and_fetch(target, 1));
}

extern __GNU_INLINE uint8_t
atomic_add_8_nv(volatile uint8_t *target, int8_t value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uchar_t
atomic_add_char_nv(volatile uchar_t *target, signed char value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uint16_t
atomic_add_16_nv(volatile uint16_t *target, int16_t value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE ushort_t
atomic_add_short_nv(volatile ushort_t *target, short value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uint32_t
atomic_add_32_nv(volatile uint32_t *target, int32_t value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uint_t
atomic_add_int_nv(volatile uint_t *target, int value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE void *
atomic_add_ptr_nv(volatile void *target, ssize_t value)
{
	return (__sync_add_and_fetch((caddr_t *)target, value));
}

extern __GNU_INLINE ulong_t
atomic_add_long_nv(volatile ulong_t *target, long value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uint64_t
atomic_add_64_nv(volatile uint64_t *target, int64_t value)
{
	return (__sync_add_and_fetch(target, value));
}

extern __GNU_INLINE uint8_t
atomic_or_8_nv(volatile uint8_t *target, uint8_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uchar_t
atomic_or_uchar_nv(volatile uchar_t *target, uchar_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uint16_t
atomic_or_16_nv(volatile uint16_t *target, uint16_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE ushort_t
atomic_or_ushort_nv(volatile ushort_t *target, ushort_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uint32_t
atomic_or_32_nv(volatile uint32_t *target, uint32_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uint_t
atomic_or_uint_nv(volatile uint_t *target, uint_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE ulong_t
atomic_or_ulong_nv(volatile ulong_t *target, ulong_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uint64_t
atomic_or_64_nv(volatile uint64_t *target, uint64_t value)
{
	return (__sync_or_and_fetch(target, value));
}

extern __GNU_INLINE uint8_t
atomic_and_8_nv(volatile uint8_t *target, uint8_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uchar_t
atomic_and_uchar_nv(volatile uchar_t *target, uchar_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uint16_t
atomic_and_16_nv(volatile uint16_t *target, uint16_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE ushort_t
atomic_and_ushort_nv(volatile ushort_t *target, ushort_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uint32_t
atomic_and_32_nv(volatile uint32_t *target, uint32_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uint_t
atomic_and_uint_nv(volatile uint_t *target, uint_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE ulong_t
atomic_and_ulong_nv(volatile ulong_t *target, ulong_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uint64_t
atomic_and_64_nv(volatile uint64_t *target, uint64_t value)
{
	return (__sync_and_and_fetch(target, value));
}

extern __GNU_INLINE uint8_t
atomic_cas_8(volatile uint8_t *target, uint8_t cmp, uint8_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uchar_t
atomic_cas_uchar(volatile uchar_t *target, uchar_t cmp, uchar_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint16_t
atomic_cas_16(volatile uint16_t *target, uint16_t cmp, uint16_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE ushort_t
atomic_cas_ushort(volatile ushort_t *target, ushort_t cmp, ushort_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint_t
atomic_cas_uint(volatile uint_t *target, uint_t cmp, uint_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE ulong_t
atomic_cas_ulong(volatile ulong_t *target, ulong_t cmp, ulong_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t cmp, uint64_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE void *
atomic_cas_ptr(volatile void *target, void *cmp, void *newval)
{
	return (__sync_val_compare_and_swap((void **)target, cmp, newval));
}

extern __GNU_INLINE uint8_t
atomic_swap_8(volatile uint8_t *target, uint8_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE uchar_t
atomic_swap_char(volatile uchar_t *target, uchar_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE uint16_t
atomic_swap_16(volatile uint16_t *target, uint16_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE ushort_t
atomic_swap_ushort(volatile ushort_t *target, ushort_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE uint32_t
atomic_swap_32(volatile uint32_t *target, uint32_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE uint_t
atomic_swap_uint(volatile uint_t *target, uint_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE uint64_t
atomic_swap_64(volatile uint64_t *target, uint64_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE void *
atomic_swap_ptr(volatile void *target, void *newval)
{
	return (__atomic_exchange_n((void **)target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE ulong_t
atomic_swap_ulong(volatile ulong_t *target, ulong_t newval)
{
	return (__atomic_exchange_n(target, newval, __ATOMIC_SEQ_CST));
}

extern __GNU_INLINE int
atomic_set_long_excl(volatile ulong_t *target, uint_t value)
{

	ulong_t bit = (1UL << value);
	return (__sync_fetch_and_or(target, bit) & bit ? -1: 0);
}

extern __GNU_INLINE int
atomic_clear_long_excl(volatile ulong_t *target, uint_t value)
{
	ulong_t bit = (1UL << value);
	return (__sync_fetch_and_and(target, ~bit) & bit ? 0: -1);
}

extern __GNU_INLINE void
membar_enter(void)
{
	__sync_synchronize();
}

extern __GNU_INLINE void
membar_exit(void)
{
	__sync_synchronize();
}

extern __GNU_INLINE void
membar_producer(void)
{
	__sync_synchronize();
}

extern __GNU_INLINE void
membar_consumer(void)
{
	__sync_synchronize();
}

extern __GNU_INLINE void
membar_sync(void)
{
	__sync_synchronize();
}

#if defined(_KERNEL)
/*
 * Legacy kernel interfaces; they will go away (eventually).
 */
extern __GNU_INLINE uint8_t
cas8(uint8_t *target, uint8_t cmp, uint8_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint32_t
cas32(uint32_t *target, uint32_t cmp, uint32_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE uint64_t
cas64(uint64_t *target, uint64_t cmp, uint64_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE ulong_t
caslong(ulong_t *target, ulong_t cmp, ulong_t newval)
{
	return (__sync_val_compare_and_swap(target, cmp, newval));
}

extern __GNU_INLINE void *
casptr(void *target, void *cmp, void *newval)
{
	return (__sync_val_compare_and_swap((void **)target, cmp, newval));
}

extern __GNU_INLINE void
atomic_or_long(ulong_t *target, ulong_t bits)
{
	(void) __sync_or_and_fetch(target, bits);
}

extern __GNU_INLINE void
atomic_and_long(ulong_t *target, ulong_t bits)
{
	(void) __sync_and_and_fetch(target, bits);
}
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _ASM_ATOMIC_H */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Hayashi Naoyuki
 * Copyright 2022 Richard Lowe
 */

/*
 * Bootstrap routine for run-time linker.
 * We get control from exec which has loaded our text and
 * data into the process' address space and created the process
 * stack.
 *
 * On entry, the process stack looks like this:
 *
 *	#_______________________#  high addresses
 *	#	strings		#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Auxiliary	#
 *	#	entries		#
 *	#	...		#
 *	#	(size varies)	#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Environment	#
 *	#	pointers	#
 *	#	...		#
 *	#	(one word each)	#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Argument	# low addresses
 *	#	pointers	#
 *	#	Argc words	#
 *	#_______________________#
 *	#	argc		#
 *	#_______________________# <- sp
 *
 *
 * We must calculate the address at which ld.so was loaded,
 * find the addr of the dynamic section of ld.so, of argv[0], and  of
 * the process' environment pointers - and pass the thing to _setup
 * to handle.  We then call _rtld - on return we jump to the entry
 * point for the a.out.
 */
#include <sys/asm_linkage.h>
#include <sys/auxv.h>
#include <link.h>

	ENTRY(_rt_boot)
	mov	x28, sp				// x28 <- boot structure from kernel
	stp	xzr, xzr, [sp, #(-8 * 2)]!	// two zeros at sp-16 and sp-8 to terminate the stack
	mov	x29, sp				// x29 <- our sp now
	sub	sp, sp, #EB_MAX_SIZE64          // reserve #EB_MAX_SIZE64 bytes of stack
	mov	x0, sp				// x0 <- eb[0]

	mov	x9, #EB_ARGV			// x9 <- #EB_ARGV tag
	add	x10, x28, #8			// x10 <- initial stack pointer + 8
	stp	x9, x10, [x0, #(8 * 0)]		// x9 and x10 (#EB_ARGV, and pointer) to eb[0]

	mov	x9, #EB_ENVP			// x9 <- #EB_ENVP tag
	ldr	x11, [x28]			// x11 <- argc
	lsl	x11, x11, #3			// x11 <- argc * 8 (bytes of arguments)
	add	x10, x11, x10			// x10 <- initial sp + (argc + argv)
	add	x10, x10, #8			// x10 <- + terminator
	stp	x9, x10, [x0, #(8 * 2)]		// x9 and x10 (#EB_ENVP and env) to eb[1]

	mov	x9, #EB_AUXV			// x9 <- #EB_AUXV
1:	ldr	x11, [x10]			// x11 <- envp
	add	x10, x10, #8			// x10 <- next envp entry???
	cbnz	x11, 1b				// loop until we hit a 0 to end the the envp
	stp	x9, x10, [x0, #(8 * 4)]		// x9 and x10 (#EB_AUXV and auxv) to eb[2]

	/*
	 * Pull the base address of ld.so out of the kernel
	 * rather than calculate it.
	 *
	 * after 3: x10 contains either the base address of the loaded ld.so
	 * or 0
	 */
1:	ldr	x11, [x10]			// <- x11 first auxv tag
	cmp	x11, #AT_NULL
	b.eq	3f				// if AT_NULL, we're out
	cmp	x11, #AT_BASE
	b.ne	2f				// not our tag, skip to the loop incr
	ldr	x10, [x10, #8]			// x10 <- base address
	b	4f				// <- break
2:	add	x10, x10, #16			// next auxv tag
	b	1b				// try again
3:	mov	x10, #0				// failed to find AT_BASE, 0 it out to make it clear
4:
	mov	x9, #EB_LDSO_BASE		// x9 <- #EB_LDSO_BASE
	stp	x9, x10, [x0, #(8 * 6)]		// x9 and x10 (#EB_LDSO_BASE, and our idea where it is) to eb[3]

	mov	x9, #EB_NULL			// x9 <- #EB_NULL
	str	x9, [x0, #(8 * 8)]		// x9 null entry to eb[4]

/*
 * Now bootstrap structure has been constructed.
 * The process stack looks like this:
 *
 *	#	...		#
 *	#_______________________#
 *	#	Argument	# high addresses
 *	#	pointers	#
 *	#	Argc words	#
 *	#_______________________#
 *	#	argc		#
 *	#_______________________# <- fp (= sp on entry)
 *	#   reserved area of    #
 *	#  bootstrap structure  #
 *	#  (currently not used) #
 *	#	...		#
 *	#_______________________#
 *	#  garbage (not used)   #
 *	#_ _ _ _ _ _ _ _ _ _ _ _#
 *	#	EB_NULL		#
 *	#_______________________# <- sp + 64 (= &eb[4])
 *	#	relocbase	#
 *	#_ _ _ _ _ _ _ _ _ _ _ _#
 *	#	EB_LDSO_BASE	#
 *	#_______________________# <- sp + 48 (= &eb[3])
 *	#	&auxv[0]	#
 *	#_ _ _ _ _ _ _ _ _ _ _ _#
 *	#	EB_AUXV		#
 *	#_______________________# <- sp + 32 (= &eb[2])
 *	#	&envp[0]	#
 *	#_ _ _ _ _ _ _ _ _ _ _ _#
 *	#	EB_ENVP		#
 *	#_______________________# <- sp + 16 (= &eb[1])
 *	#	&argv[0]	#
 *	#_ _ _ _ _ _ _ _ _ _ _ _# low addresses
 *	#	EB_ARGV		#
 *	#_______________________# <- sp (= fp - EB_MAX_SIZE64) = a0 (= &eb[0])
 */

	bl	2f					// skip constant, set lr to its address
 1:	.quad _DYNAMIC - 1b
 2:	ldr	x1, [lr]				// x1 = offset from 1b to _DYNAMIC at compile time
	adr	x10, 1b					// x10 <- address of 1b at runtime
	add	x1, x1, x10				// x1 <- runtime address of 1b +
							//   offset from 1b to _DYNAMIC at compile time

	bl	_setup					// _setup(Boot*, Dyn*)

	add	sp, sp, #EB_MAX_SIZE64			// put the EB block back to the stack
	add	sp, sp, #(8 * 2)			// put 2 extra entries (x0 and x1?)

	adrp	x2, :got:atexit_fini			// page of atexit_fini in the GOT
	ldr	x2, [x2, #:got_lo12:atexit_fini]	// lo12 bits filled out, x2 atexit_fini

	br	x0					// get going with our main entry
	SET_SIZE(_rt_boot)

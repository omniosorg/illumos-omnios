# kmdb on ARM

## Exception handling

Everything we do is driven by ARM exceptions.  When kmdb is loaded either at
boot or module load time, we swap out the exception vector of any CPU with our
own, which mostly passes along to the usual system vector with the exception
of synchronous exceptions from EL1 which are handled specially.

We swap the entire vector rather than patching a single one, or adjusting
indirection through function pointers since it's proved the most foolproof in
practice.

## Entering the debugger

We always enter kmdb via an exception.  For manual entry we enter via a `svc`
from EL1 back to EL1, similarly to a system call.  Other entry occurs as we
handle the relevant ARM synchronous exceptions.

When we take a synchronous exception at EL1 our handler saves a full set of
registers and calls `kdi_cmnint` which is the heart of all our exception
handling.  This is much like on Intel, with the exception that on Intel only
the specific faults desired can be be directed to `kdi_cmnint` whereas on ARM
we have to take every synchronous exception.

`kdi_cmnint` adds a crumb to the cpusave ringbuffer (for debugging with
`::crumbs`).  Unfortunately because as mentioned every syncronous EL1
exception reaches here, this turns into traptrace with a very short ring
buffer, but has nevertheless proved useful.

Next we have to check whether it was the kernel that was running when we took
the fault, or kmdb ourselves.  If the faulting thread was running in the
debugger `kdi_dvec_handle_fault` decides what to do (either jump to a fault
handler, or prepare to debug itself).  Otherwise we call
`kdi_save_common_state` to set up the `kdi_cpusave_t`, this means pointing it
to our already saved registers saving the current exception vector.

To determine whether the debugger or kernel should handle the trap, we call
`kdi_trap_pass`, which makes a simple judgement based on exception code.  We
can't be as careful as on Intel (where we accept anything we can't prove isn't
ours) here because on ARM we receive (in theory) any possible synchronous
exception, not only a small selection.

For traps we don't want `kdi_pass_to_kernel` will fix the CPU state, unwind
the stack, and call `from_current_el_sync_handler` our regular handler.

For traps we do want we call `kdi_debugger_entry` which calls the main
platform-independent kmdb entry point, passing along the cpusave area we have
prepared.

On return we synchronize debug registers (see below), and return up the stack,
eventually to an `eret` to where the kernel received the trap.

# Breakpoints

Only software breakpoints with an immediate of 0 (that is, `brk #0`) are used
by the implementation, and the implementation is straight forward thanks to
fixed size instructions.

# Watchpoints

A shadow set of watchpoint register pairs (`DBGWVRn_EL1`/`DBGWCRn_EL1`),
stored as an array of `kdi_waptreg_t` and maintained by
`kmdb_kdi_read_waptreg`/`kmdb_kdi_update_wapreg` (the `kdi_waptreg_t` contains
its own number).

Claiming exclusive ownership of the EL1 debug registers, we synch this
unidirectionally, out into the hardware, via `kdi_restore_debugging_state`,
called by `kdi_resume` each time we leave kmdb and head off into the world.
There is no inbound synchronization, but if there were it would be in
`kdi_save_common_state`.

# Single Step

Single step adds the `PSR.SS` and `PSR.I` bits to enable hardware stepping,
and mask interrupts respectively, and clears `PSR.D` to allow debug
exceptions.

We then set `MDSCR.SS` and call `kmdb_dpi_resume_master` which returns back
out to the kernel, immediately takes a single step trap, and comes right back
again, where we undo our register changes.

# Debug exceptions and their masking v. single step

There are various ways in which debug exceptions may be masked (for the
purposes of this, I'm including in "masked" the case where the CPU never
bothers generating them).

- `PSTATE.D`: The "D" in "DAIF", masks all debug exceptions.
- `MDSCR.MDE`: "monitor debug events", necessary for (hardware)
  breakpoints and watchpoints.
- `MDSCR.KDE`: "kernel debug enable", allows debug exceptions from ELn to be
  handled at ELn

Our policy is that while in the debugger, `PSTATE.D == 1` and no debug
exceptions may occur.  When we go back into the kernel we clear `PSTATE.D`.
Inside the kernel, we clear `PSTATE.D` just after taking exceptions.

This isn't awful but `MDSCR.SS`, the hardware single step control, spoils the
party.  Because our default configuration when running in the kernel with kmdb
loaded is that debug exceptions are unmasked, and debug exceptions are enabled
from EL1 to EL1, when userland requests a single step, there is a window where
we need to set `MDSCR.SS` which would immediately then single step trap from
the *kernel*.

We solve this by proxying the value of `MDSCR.SS` in userland on `PSTATE.SS`,
when returning to userland we set `MDSCR.SS` if `SPSR.SS` is non-0.  On
returning from userland we clear `MDSCR.SS` unconditionally.

This seems to work, but feels like there are gaps and

XXXARM: should be thought about carefully

The most obvious gap is that -- like on Intel -- we should forbid
single-stepping the debugger in places this will go horridly wrong.

# single step v. traps and system calls

On Intel kmdb knows the places it cannot safely step because of a hardcoded
list of functions at initialization time that do unsafe things.

On ARM these things would be returning via `eret`, setting `PSTATE.D` or
manipulating `MDSCR.SS`.  We don't implement this yet as -- similar to trap
handling -- with things in flux maintaining this hardcoded list is incredibly
error prone.

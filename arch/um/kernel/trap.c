// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 */

#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/sched/debug.h>
#include <asm/current.h>
#include <asm/tlbflush.h>
#include <arch.h>
#include <as-layout.h>
#include <kern_util.h>
#include <os.h>
#include <skas.h>

/*
 * NOTE: UML does not have exception tables. As such, this is almost a copy
 * of the code in mm/memory.c, only adjusting the logic to simply check whether
 * we are coming from the kernel instead of doing an additional lookup in the
 * exception table.
 * We can do this simplification because we never get here if the exception was
 * fixable.
 */
static inline bool get_mmap_lock_carefully(struct mm_struct *mm, bool is_user)
{
	if (likely(mmap_read_trylock(mm)))
		return true;

	if (!is_user)
		return false;

	return !mmap_read_lock_killable(mm);
}

static inline bool mmap_upgrade_trylock(struct mm_struct *mm)
{
	/*
	 * We don't have this operation yet.
	 *
	 * It should be easy enough to do: it's basically a
	 *    atomic_long_try_cmpxchg_acquire()
	 * from RWSEM_READER_BIAS -> RWSEM_WRITER_LOCKED, but
	 * it also needs the proper lockdep magic etc.
	 */
	return false;
}

static inline bool upgrade_mmap_lock_carefully(struct mm_struct *mm, bool is_user)
{
	mmap_read_unlock(mm);
	if (!is_user)
		return false;

	return !mmap_write_lock_killable(mm);
}

/*
 * Helper for page fault handling.
 *
 * This is kind of equivalend to "mmap_read_lock()" followed
 * by "find_extend_vma()", except it's a lot more careful about
 * the locking (and will drop the lock on failure).
 *
 * For example, if we have a kernel bug that causes a page
 * fault, we don't want to just use mmap_read_lock() to get
 * the mm lock, because that would deadlock if the bug were
 * to happen while we're holding the mm lock for writing.
 *
 * So this checks the exception tables on kernel faults in
 * order to only do this all for instructions that are actually
 * expected to fault.
 *
 * We can also actually take the mm lock for writing if we
 * need to extend the vma, which helps the VM layer a lot.
 */
static struct vm_area_struct *
um_lock_mm_and_find_vma(struct mm_struct *mm,
			unsigned long addr, bool is_user)
{
	struct vm_area_struct *vma;

	if (!get_mmap_lock_carefully(mm, is_user))
		return NULL;

	vma = find_vma(mm, addr);
	if (likely(vma && (vma->vm_start <= addr)))
		return vma;

	/*
	 * Well, dang. We might still be successful, but only
	 * if we can extend a vma to do so.
	 */
	if (!vma || !(vma->vm_flags & VM_GROWSDOWN)) {
		mmap_read_unlock(mm);
		return NULL;
	}

	/*
	 * We can try to upgrade the mmap lock atomically,
	 * in which case we can continue to use the vma
	 * we already looked up.
	 *
	 * Otherwise we'll have to drop the mmap lock and
	 * re-take it, and also look up the vma again,
	 * re-checking it.
	 */
	if (!mmap_upgrade_trylock(mm)) {
		if (!upgrade_mmap_lock_carefully(mm, is_user))
			return NULL;

		vma = find_vma(mm, addr);
		if (!vma)
			goto fail;
		if (vma->vm_start <= addr)
			goto success;
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto fail;
	}

	if (expand_stack_locked(vma, addr))
		goto fail;

success:
	mmap_write_downgrade(mm);
	return vma;

fail:
	mmap_write_unlock(mm);
	return NULL;
}

/*
 * Note this is constrained to return 0, -EFAULT, -EACCES, -ENOMEM by
 * segv().
 */
int handle_page_fault(unsigned long address, unsigned long ip,
		      int is_write, int is_user, int *code_out)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	pmd_t *pmd;
	pte_t *pte;
	int err = -EFAULT;
	unsigned int flags = FAULT_FLAG_DEFAULT;

	*code_out = SEGV_MAPERR;

	/*
	 * If the fault was with pagefaults disabled, don't take the fault, just
	 * fail.
	 */
	if (faulthandler_disabled())
		goto out_nosemaphore;

	if (is_user)
		flags |= FAULT_FLAG_USER;
retry:
	vma = um_lock_mm_and_find_vma(mm, address, is_user);
	if (!vma)
		goto out_nosemaphore;

	*code_out = SEGV_ACCERR;
	if (is_write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto out;
		flags |= FAULT_FLAG_WRITE;
	} else {
		/* Don't require VM_READ|VM_EXEC for write faults! */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC)))
			goto out;
	}

	do {
		vm_fault_t fault;

		fault = handle_mm_fault(vma, address, flags, NULL);

		if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
			goto out_nosemaphore;

		/* The fault is fully completed (including releasing mmap lock) */
		if (fault & VM_FAULT_COMPLETED)
			return 0;

		if (unlikely(fault & VM_FAULT_ERROR)) {
			if (fault & VM_FAULT_OOM) {
				goto out_of_memory;
			} else if (fault & VM_FAULT_SIGSEGV) {
				goto out;
			} else if (fault & VM_FAULT_SIGBUS) {
				err = -EACCES;
				goto out;
			}
			BUG();
		}
		if (fault & VM_FAULT_RETRY) {
			flags |= FAULT_FLAG_TRIED;

			goto retry;
		}

		pmd = pmd_off(mm, address);
		pte = pte_offset_kernel(pmd, address);
	} while (!pte_present(*pte));
	err = 0;
	/*
	 * The below warning was added in place of
	 *	pte_mkyoung(); if (is_write) pte_mkdirty();
	 * If it's triggered, we'd see normally a hang here (a clean pte is
	 * marked read-only to emulate the dirty bit).
	 * However, the generic code can mark a PTE writable but clean on a
	 * concurrent read fault, triggering this harmlessly. So comment it out.
	 */
#if 0
	WARN_ON(!pte_young(*pte) || (is_write && !pte_dirty(*pte)));
#endif
	flush_tlb_page(vma, address);
out:
	mmap_read_unlock(mm);
out_nosemaphore:
	return err;

out_of_memory:
	/*
	 * We ran out of memory, call the OOM killer, and return the userspace
	 * (which will retry the fault, or kill us if we got oom-killed).
	 */
	mmap_read_unlock(mm);
	if (!is_user)
		goto out_nosemaphore;
	pagefault_out_of_memory();
	return 0;
}

static void show_segv_info(struct uml_pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct faultinfo *fi = UPT_FAULTINFO(regs);

	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %px sp %px error %x",
		task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
		tsk->comm, task_pid_nr(tsk), FAULT_ADDRESS(*fi),
		(void *)UPT_IP(regs), (void *)UPT_SP(regs),
		fi->error_code);

	print_vma_addr(KERN_CONT " in ", UPT_IP(regs));
	printk(KERN_CONT "\n");
}

static void bad_segv(struct faultinfo fi, unsigned long ip)
{
	current->thread.arch.faultinfo = fi;
	force_sig_fault(SIGSEGV, SEGV_ACCERR, (void __user *) FAULT_ADDRESS(fi));
}

void fatal_sigsegv(void)
{
	force_fatal_sig(SIGSEGV);
	do_signal(&current->thread.regs);
	/*
	 * This is to tell gcc that we're not returning - do_signal
	 * can, in general, return, but in this case, it's not, since
	 * we just got a fatal SIGSEGV queued.
	 */
	os_dump_core();
}

/**
 * segv_handler() - the SIGSEGV handler
 * @sig:	the signal number
 * @unused_si:	the signal info struct; unused in this handler
 * @regs:	the ptrace register information
 *
 * The handler first extracts the faultinfo from the UML ptrace regs struct.
 * If the userfault did not happen in an UML userspace process, bad_segv is called.
 * Otherwise the signal did happen in a cloned userspace process, handle it.
 */
void segv_handler(int sig, struct siginfo *unused_si, struct uml_pt_regs *regs)
{
	struct faultinfo * fi = UPT_FAULTINFO(regs);

	if (UPT_IS_USER(regs) && !SEGV_IS_FIXABLE(fi)) {
		show_segv_info(regs);
		bad_segv(*fi, UPT_IP(regs));
		return;
	}
	segv(*fi, UPT_IP(regs), UPT_IS_USER(regs), regs);
}

/*
 * We give a *copy* of the faultinfo in the regs to segv.
 * This must be done, since nesting SEGVs could overwrite
 * the info in the regs. A pointer to the info then would
 * give us bad data!
 */
unsigned long segv(struct faultinfo fi, unsigned long ip, int is_user,
		   struct uml_pt_regs *regs)
{
	jmp_buf *catcher;
	int si_code;
	int err;
	int is_write = FAULT_WRITE(fi);
	unsigned long address = FAULT_ADDRESS(fi);

	if (!is_user && regs)
		current->thread.segv_regs = container_of(regs, struct pt_regs, regs);

	if (!is_user && (address >= start_vm) && (address < end_vm)) {
		flush_tlb_kernel_vm();
		goto out;
	}
	else if (current->mm == NULL) {
		show_regs(container_of(regs, struct pt_regs, regs));
		panic("Segfault with no mm");
	}
	else if (!is_user && address > PAGE_SIZE && address < TASK_SIZE) {
		show_regs(container_of(regs, struct pt_regs, regs));
		panic("Kernel tried to access user memory at addr 0x%lx, ip 0x%lx",
		       address, ip);
	}

	if (SEGV_IS_FIXABLE(&fi))
		err = handle_page_fault(address, ip, is_write, is_user,
					&si_code);
	else {
		err = -EFAULT;
		/*
		 * A thread accessed NULL, we get a fault, but CR2 is invalid.
		 * This code is used in __do_copy_from_user() of TT mode.
		 * XXX tt mode is gone, so maybe this isn't needed any more
		 */
		address = 0;
	}

	catcher = current->thread.fault_catcher;
	if (!err)
		goto out;
	else if (catcher != NULL) {
		current->thread.fault_addr = (void *) address;
		UML_LONGJMP(catcher, 1);
	}
	else if (current->thread.fault_addr != NULL)
		panic("fault_addr set but no fault catcher");
	else if (!is_user && arch_fixup(ip, regs))
		goto out;

	if (!is_user) {
		show_regs(container_of(regs, struct pt_regs, regs));
		panic("Kernel mode fault at addr 0x%lx, ip 0x%lx",
		      address, ip);
	}

	show_segv_info(regs);

	if (err == -EACCES) {
		current->thread.arch.faultinfo = fi;
		force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address);
	} else {
		BUG_ON(err != -EFAULT);
		current->thread.arch.faultinfo = fi;
		force_sig_fault(SIGSEGV, si_code, (void __user *) address);
	}

out:
	if (regs)
		current->thread.segv_regs = NULL;

	return 0;
}

void relay_signal(int sig, struct siginfo *si, struct uml_pt_regs *regs)
{
	int code, err;
	if (!UPT_IS_USER(regs)) {
		if (sig == SIGBUS)
			printk(KERN_ERR "Bus error - the host /dev/shm or /tmp "
			       "mount likely just ran out of space\n");
		panic("Kernel mode signal %d", sig);
	}

	arch_examine_signal(sig, regs);

	/* Is the signal layout for the signal known?
	 * Signal data must be scrubbed to prevent information leaks.
	 */
	code = si->si_code;
	err = si->si_errno;
	if ((err == 0) && (siginfo_layout(sig, code) == SIL_FAULT)) {
		struct faultinfo *fi = UPT_FAULTINFO(regs);
		current->thread.arch.faultinfo = *fi;
		force_sig_fault(sig, code, (void __user *)FAULT_ADDRESS(*fi));
	} else {
		printk(KERN_ERR "Attempted to relay unknown signal %d (si_code = %d) with errno %d\n",
		       sig, code, err);
		force_sig(sig);
	}
}

void bus_handler(int sig, struct siginfo *si, struct uml_pt_regs *regs)
{
	if (current->thread.fault_catcher != NULL)
		UML_LONGJMP(current->thread.fault_catcher, 1);
	else
		relay_signal(sig, si, regs);
}

void winch(int sig, struct siginfo *unused_si, struct uml_pt_regs *regs)
{
	do_IRQ(WINCH_IRQ, regs);
}

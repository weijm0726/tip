#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>

/*
 * Routines for handling mm_structs
 */
extern struct mm_struct * mm_alloc(void);

/* mmdrop drops the mm and the page tables */
extern void __mmdrop(struct mm_struct *);
static inline void mmdrop(struct mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__mmdrop(mm);
}

static inline void mmdrop_async_fn(struct work_struct *work)
{
	struct mm_struct *mm = container_of(work, struct mm_struct, async_put_work);
	__mmdrop(mm);
}

static inline void mmdrop_async(struct mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count))) {
		INIT_WORK(&mm->async_put_work, mmdrop_async_fn);
		schedule_work(&mm->async_put_work);
	}
}

static inline bool mmget_not_zero(struct mm_struct *mm)
{
	return atomic_inc_not_zero(&mm->mm_users);
}

/* mmput gets rid of the mappings and all user-space */
extern void mmput(struct mm_struct *);
#ifdef CONFIG_MMU
/* same as above but performs the slow path from the async context. Can
 * be called from the atomic context as well
 */
extern void mmput_async(struct mm_struct *);
#endif

/* Grab a reference to a task's mm, if it is not already going away */
extern struct mm_struct *get_task_mm(struct task_struct *task);
/*
 * Grab a reference to a task's mm, if it is not already going away
 * and ptrace_may_access with the mode parameter passed to it
 * succeeds.
 */
extern struct mm_struct *mm_access(struct task_struct *task, unsigned int mode);
/* Remove the current tasks stale references to the old mm_struct */
extern void mm_release(struct task_struct *, struct mm_struct *);

#endif /* _LINUX_SCHED_MM_H */

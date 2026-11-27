/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_REVELATOR_H
#define _LINUX_REVELATOR_H

#include <linux/init.h>
#include <linux/types.h>

struct mm_struct;

#ifdef CONFIG_REVELATOR
#include <linux/jump_label.h>
#include <linux/spinlock_types.h>

struct revelator_mm {
	u64 id;
	u64 secret;
	u32 algorithm;
	raw_spinlock_t lock;
	/* Cumulative results, indexed by allocation tier (0 is fallback). */
	u64 data[4];
	u64 pt[2];
};

DECLARE_STATIC_KEY_FALSE(revelator_placement);

void __init revelator_init(void);
void revelator_init_mm(struct mm_struct *mm);
unsigned int revelator_hash_id(void);
unsigned int __revelator_candidates(struct mm_struct *mm, unsigned long addr,
				    bool table, unsigned long pfns[3]);

static inline unsigned int revelator_candidates(struct mm_struct *mm,
						unsigned long addr, bool table,
						unsigned long pfns[3])
{
	if (static_branch_unlikely(&revelator_placement))
		return __revelator_candidates(mm, addr, table, pfns);
	return 0;
}

/* Call once for each successful allocation attempted with candidates. */
void revelator_account(struct mm_struct *mm, unsigned long addr, bool table,
		       unsigned int tier, unsigned long pfn);

#else /* CONFIG_REVELATOR */
static inline void revelator_init(void) { }
static inline void revelator_init_mm(struct mm_struct *mm) { }

static inline unsigned int revelator_candidates(struct mm_struct *mm,
						unsigned long addr, bool table,
						unsigned long pfns[3])
{
	return 0;
}

static inline void revelator_account(struct mm_struct *mm, unsigned long addr,
				     bool table, unsigned int tier, unsigned long pfn)
{
}
#endif /* CONFIG_REVELATOR */

#endif /* _LINUX_REVELATOR_H */

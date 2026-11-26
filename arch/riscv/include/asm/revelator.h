/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_REVELATOR_H
#define _ASM_RISCV_REVELATOR_H

#include <linux/types.h>

struct mm_struct;

#ifdef CONFIG_REVELATOR
#include <linux/jump_label.h>

DECLARE_STATIC_KEY_FALSE(riscv_revelator_csr);

static inline bool riscv_revelator_enabled(void)
{
	return static_branch_unlikely(&riscv_revelator_csr);
}

/* The switch holds local IRQs disabled from disable through bind. */
void riscv_revelator_disable(void);
void riscv_revelator_bind(struct mm_struct *mm);
/* The accounting lock and local IRQ disable cover the whole snapshot. */
void riscv_revelator_refresh(struct mm_struct *mm);
#else
static inline bool riscv_revelator_enabled(void) { return false; }
static inline void riscv_revelator_disable(void) { }
static inline void riscv_revelator_bind(struct mm_struct *mm) { }
#endif

#endif /* _ASM_RISCV_REVELATOR_H */

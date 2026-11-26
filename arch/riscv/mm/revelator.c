// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpuhotplug.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/of.h>
#include <linux/percpu.h>
#include <linux/revelator.h>

#include <asm/asm-extable.h>
#include <asm/csr.h>
#include <asm/revelator.h>

#define REVELATOR_ABI_VERSION	1
#define CSR_REVELATOR_CONTROL	0x5c0
#define CSR_REVELATOR_MM_ID	0x5c1
#define CSR_REVELATOR_SECRET	0x5c2
#define CSR_REVELATOR_SATP	0x5c3
#define CSR_REVELATOR_TIER1	0x5c4
#define CSR_REVELATOR_TIER2	0x5c5
#define CSR_REVELATOR_TIER3	0x5c6
#define CSR_REVELATOR_FALLBACK	0x5c7

#define REVELATOR_DISABLE	0
#define REVELATOR_BIND		1
#define REVELATOR_REFRESH	2
#define REVELATOR_WINDOW	64

DEFINE_STATIC_KEY_FALSE(riscv_revelator_csr);

struct revelator_hart {
	bool available;
	u64 id;
	u64 sent_total;
};

static DEFINE_PER_CPU(struct revelator_hart, revelator_hart);

static inline unsigned long revelator_read_version(void)
{
	unsigned long version = 0;

	/* A malformed DT or a different hart may not implement this CSR. */
	asm volatile("1: csrr %0, " __stringify(CSR_REVELATOR_CONTROL) "\n"
		     "2:\n"
		     _ASM_EXTABLE(1b, 2b)
		     : "+r" (version) : : "memory");
	return version;
}

static u64 revelator_total(const struct revelator_mm *state)
{
	return state->data[0] + state->data[1] + state->data[2] + state->data[3];
}

static void revelator_write_counts(const struct revelator_mm *state)
{
	lockdep_assert_held(&state->lock);
	csr_write(CSR_REVELATOR_TIER1, state->data[1]);
	csr_write(CSR_REVELATOR_TIER2, state->data[2]);
	csr_write(CSR_REVELATOR_TIER3, state->data[3]);
	csr_write(CSR_REVELATOR_FALLBACK, state->data[0]);
}

void riscv_revelator_disable(void)
{
	struct revelator_hart *hart = this_cpu_ptr(&revelator_hart);

	lockdep_assert_irqs_disabled();
	if (!hart->available)
		return;

	csr_write(CSR_REVELATOR_CONTROL, REVELATOR_DISABLE);
	hart->id = 0;
}

void riscv_revelator_bind(struct mm_struct *mm)
{
	struct revelator_hart *hart = this_cpu_ptr(&revelator_hart);
	struct revelator_mm *state = &mm->revelator;

	lockdep_assert_irqs_disabled();
	if (!hart->available || !state->id)
		return;

	/* IRQs are still disabled across the satp change and the whole commit. */
	raw_spin_lock(&state->lock);
	csr_write(CSR_REVELATOR_MM_ID, state->id);
	csr_write(CSR_REVELATOR_SECRET, state->secret);
	csr_write(CSR_REVELATOR_SATP, csr_read(CSR_SATP));
	revelator_write_counts(state);
	csr_write(CSR_REVELATOR_CONTROL, REVELATOR_BIND);
	hart->id = state->id;
	hart->sent_total = revelator_total(state);
	raw_spin_unlock(&state->lock);
}

void riscv_revelator_refresh(struct mm_struct *mm)
{
	struct revelator_hart *hart = this_cpu_ptr(&revelator_hart);
	struct revelator_mm *state = &mm->revelator;
	u64 total;

	lockdep_assert_irqs_disabled();
	if (hart->id != state->id)
		return;

	/* Each allocating hart publishes after one window of per-mm results. */
	total = revelator_total(state);
	if (total - hart->sent_total < REVELATOR_WINDOW)
		return;

	revelator_write_counts(state);
	csr_write(CSR_REVELATOR_CONTROL, REVELATOR_REFRESH);
	hart->sent_total = total;
}

static int revelator_cpu_online(unsigned int cpu)
{
	struct revelator_hart *hart = per_cpu_ptr(&revelator_hart, cpu);
	unsigned long flags;

	local_irq_save(flags);
	hart->available = revelator_read_version() == REVELATOR_ABI_VERSION;
	riscv_revelator_disable();
	local_irq_restore(flags);
	return 0;
}

static int revelator_cpu_offline(unsigned int cpu)
{
	struct revelator_hart *hart = per_cpu_ptr(&revelator_hart, cpu);
	unsigned long flags;

	local_irq_save(flags);
	riscv_revelator_disable();
	hart->available = false;
	local_irq_restore(flags);
	return 0;
}

static int __init riscv_revelator_init(void)
{
	struct device_node *root;
	u32 version;
	int ret;

	if (!static_branch_unlikely(&revelator_placement))
		return 0;

	root = of_find_node_by_path("/");
	if (!root)
		return 0;
	ret = of_property_read_variable_u32_array(root, "revelator,abi-version",
						  &version, 1, 1);
	of_node_put(root);
	if (ret != 1 || version != REVELATOR_ABI_VERSION)
		return 0;

	/* Trap handling is installed; probe on each hart before using the ABI. */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "riscv/revelator:online",
			       revelator_cpu_online, revelator_cpu_offline);
	if (ret < 0)
		return ret;

	static_branch_enable(&riscv_revelator_csr);
	return 0;
}
arch_initcall(riscv_revelator_init);

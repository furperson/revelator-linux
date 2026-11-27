// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/revelator.h>
#include <linux/string.h>

#include <asm/csr.h>
#include <asm/revelator.h>

#define CREATE_TRACE_POINTS
#include <trace/events/revelator.h>

#include "revelator_hash.h"

DEFINE_STATIC_KEY_FALSE(revelator_placement);

static atomic64_t revelator_next_id = ATOMIC64_INIT(0);
static bool revelator_place_tables __ro_after_init;

static enum {
	REVELATOR_OFF,
	REVELATOR_DATA,
	REVELATOR_DATA_PT,
} revelator_mode __initdata;
static enum revelator_hash_algorithm revelator_algorithm =
	REVELATOR_HASH_CITYHASH;

static int __init revelator_parse_hash(char *hash)
{
	if (!hash)
		return -EINVAL;
	if (!strcmp(hash, "cityhash"))
		revelator_algorithm = REVELATOR_HASH_CITYHASH;
	else if (!strcmp(hash, "mix13"))
		revelator_algorithm = REVELATOR_HASH_MIX13;
	else if (!strcmp(hash, "multiply-shift"))
		revelator_algorithm = REVELATOR_HASH_MULTIPLY_SHIFT;
	else
		return -EINVAL;
	return 0;
}
early_param("revelator_hash", revelator_parse_hash);

unsigned int revelator_hash_id(void)
{
	return revelator_algorithm;
}


static int __init revelator_parse_mode(char *mode)
{
	if (!mode)
		return -EINVAL;
	if (!strcmp(mode, "off"))
		revelator_mode = REVELATOR_OFF;
	else if (!strcmp(mode, "data"))
		revelator_mode = REVELATOR_DATA;
	else if (!strcmp(mode, "data+pt"))
		revelator_mode = REVELATOR_DATA_PT;
	else
		return -EINVAL;
	return 0;
}
early_param("revelator", revelator_parse_mode);

static bool __init revelator_check_ram(void)
{
	phys_addr_t end = REVELATOR_RAM_BASE;
	struct memblock_region *region;
	int ram_nid = NUMA_NO_NODE;

	/* Reserved ranges (including DT no-map ranges) may split the bank. */
	for_each_mem_region(region) {
		if (region->base != end || region->size > REVELATOR_RAM_END - end ||
		    region->flags & (MEMBLOCK_HOTPLUG | MEMBLOCK_DRIVER_MANAGED))
			return false;
		end += region->size;

		if (!memblock_is_nomap(region)) {
			int nid = memblock_get_region_node(region);

			if (nid == NUMA_NO_NODE ||
			    (ram_nid != NUMA_NO_NODE && ram_nid != nid))
				return false;
			ram_nid = nid;
		}
	}

	return end == REVELATOR_RAM_END && ram_nid != NUMA_NO_NODE;
}

void __init revelator_init(void)
{
	if (revelator_mode == REVELATOR_OFF)
		return;
	if (PAGE_SHIFT != REVELATOR_PAGE_SHIFT || satp_mode != SATP_MODE_48 ||
	    !revelator_check_ram()) {
		pr_warn("Revelator: placement disabled: requires Sv48, 4 KiB pages and single-node RAM [0x80000000, 0x100000000)\n");
		revelator_mode = REVELATOR_OFF;
	}
}

static int __init revelator_enable(void)
{
	if (revelator_mode == REVELATOR_OFF)
		return 0;

	revelator_place_tables = revelator_mode == REVELATOR_DATA_PT;
	static_branch_enable(&revelator_placement);
	pr_info("Revelator: %s placement enabled\n",
		revelator_place_tables ? "data+pt" : "data");
	return 0;
}
early_initcall(revelator_enable);

void revelator_init_mm(struct mm_struct *mm)
{
	struct revelator_mm *state = &mm->revelator;

	/* dup_mm() copies the parent's mm before we initialize the new one. */
	state->id = 0;
	state->secret = 0;
	state->algorithm = REVELATOR_HASH_CITYHASH;
	if (!static_branch_unlikely(&revelator_placement) || !rng_is_initialized())
		return;

	raw_spin_lock_init(&state->lock);
	memset(state->data, 0, sizeof(state->data));
	memset(state->pt, 0, sizeof(state->pt));
	state->secret = get_random_u64();
	state->id = atomic64_inc_return_relaxed(&revelator_next_id);
	state->algorithm = revelator_hash_id();
}

unsigned int __revelator_candidates(struct mm_struct *mm, unsigned long addr,
				    bool table, unsigned long pfns[3])
{
	struct revelator_mm *state = &mm->revelator;
	unsigned int nr = table ? 1 : 3;
	u64 base = 0;

	if (!state->id || (table && !revelator_place_tables))
		return 0;

	if (state->algorithm == REVELATOR_HASH_CITYHASH)
		base = revelator_hash_base(revelator_key(addr, table), state->id,
					   state->secret);
	for (unsigned int i = 0; i < nr; i++) {
		u64 hash;

		if (state->algorithm == REVELATOR_HASH_CITYHASH)
			hash = revelator_hash_seed(base, i + 1);
		else
			hash = revelator_hash_compact(revelator_key(addr, table),
						     state->id, state->secret,
						     i + 1, state->algorithm);
		pfns[i] = revelator_pfn(hash);
	}
	return nr;
}


void revelator_account(struct mm_struct *mm, unsigned long addr, bool table,
		       unsigned int tier, unsigned long pfn)
{
	struct revelator_mm *state = &mm->revelator;
	unsigned long flags;
	u64 count;

	raw_spin_lock_irqsave(&state->lock, flags);
	if (table) {
		count = ++state->pt[tier];
	} else {
		count = ++state->data[tier];
		if (riscv_revelator_enabled())
			riscv_revelator_refresh(mm);
	}
	raw_spin_unlock_irqrestore(&state->lock, flags);

	trace_revelator_alloc(state->id, revelator_vpn(addr), table, tier, pfn, count);
}

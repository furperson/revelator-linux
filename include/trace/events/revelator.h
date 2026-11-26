/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM revelator

#if !defined(_TRACE_REVELATOR_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_REVELATOR_H

#include <linux/tracepoint.h>

TRACE_EVENT(revelator_alloc,

	TP_PROTO(u64 mm_id, u64 vpn, bool table, unsigned int tier,
		 unsigned long pfn, u64 count),
	TP_ARGS(mm_id, vpn, table, tier, pfn, count),

	TP_STRUCT__entry(
		__field(u64, mm_id)
		__field(u64, vpn)
		__field(bool, table)
		__field(unsigned int, tier)
		__field(unsigned long, pfn)
		__field(u64, count)
	),

	TP_fast_assign(
		__entry->mm_id = mm_id;
		__entry->vpn = vpn;
		__entry->table = table;
		__entry->tier = tier;
		__entry->pfn = pfn;
		__entry->count = count;
	),

	TP_printk("mm_id=%llu vpn=%#llx table=%u tier=%u pfn=%#lx count=%llu",
		  __entry->mm_id, __entry->vpn, __entry->table, __entry->tier,
		  __entry->pfn, __entry->count)
);

#endif /* _TRACE_REVELATOR_H */

#include <trace/define_trace.h>

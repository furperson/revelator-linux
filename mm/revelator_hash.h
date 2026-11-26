/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2011 Google, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Fixed 24-byte specialization of CityHash64WithSeed at upstream revision
 * 8af9b8c2b889d80c22d6bc26ba0df1afb79a30db (google/cityhash).
 */
#ifndef _MM_REVELATOR_HASH_H
#define _MM_REVELATOR_HASH_H

#include <linux/bitops.h>
#include <linux/types.h>

#define REVELATOR_RAM_BASE	0x80000000ULL
#define REVELATOR_RAM_END	0x100000000ULL
#define REVELATOR_PAGE_SHIFT	12
#define REVELATOR_PFN_BASE	(REVELATOR_RAM_BASE >> REVELATOR_PAGE_SHIFT)
#define REVELATOR_PFN_COUNT	((REVELATOR_RAM_END - REVELATOR_RAM_BASE) >> \
				 REVELATOR_PAGE_SHIFT)

static inline u64 revelator_hash_len16(u64 u, u64 v, u64 mul)
{
	u64 a = (u ^ v) * mul;
	u64 b;

	a ^= a >> 47;
	b = (v ^ a) * mul;
	b ^= b >> 47;
	return b * mul;
}

static inline u64 revelator_hash_base(u64 x, u64 id, u64 secret)
{
	const u64 k1 = 0xb492b66fbe98f273ULL;
	const u64 k2 = 0x9ae16a3b2f90404fULL;
	const u64 mul = k2 + 2 * 24;
	/* Fetch64 of LE64(x) || LE64(id) || LE64(secret), without a buffer. */
	u64 a = x * k1;
	u64 c = secret * mul;
	u64 d = id * k2;

	return revelator_hash_len16(ror64(a + id, 43) + ror64(c, 30) + d,
				    a + ror64(id + k2, 18) + c, mul) - k2;
}

static inline u64 revelator_hash_seed(u64 base, u64 seed)
{
	return revelator_hash_len16(base, seed, 0x9ddfea08eb382d69ULL);
}

static inline unsigned long revelator_pfn(u64 hash)
{
	return REVELATOR_PFN_BASE + hash % REVELATOR_PFN_COUNT;
}

static inline u64 revelator_vpn(unsigned long addr)
{
	return (addr & GENMASK_ULL(47, 0)) >> REVELATOR_PAGE_SHIFT;
}

static inline u64 revelator_key(unsigned long addr, bool table)
{
	u64 vpn = revelator_vpn(addr);

	return table ? vpn >> 9 : vpn;
}

#endif /* _MM_REVELATOR_HASH_H */

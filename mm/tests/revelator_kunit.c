// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/sizes.h>

#include "../revelator_hash.h"

static void revelator_hash_vectors(struct kunit *test)
{
	/* Reference results from Abseil's independent CityHash64WithSeed. */
	static const struct {
		u64 x;
		u64 id;
		u64 secret;
		u64 hashes[3];
		unsigned long pfns[3];
	} vectors[] = {
		{
			0, 0, 0,
			{ 0x06b61520a4800162ULL, 0xd8b976a7c6e21e04ULL,
			  0xb0c4450ca4e4f842ULL },
			{ 0x80162, 0xa1e04, 0xcf842 },
		}, {
			0x10000000, 1, 2,
			{ 0x5b4ef3d9f6cb63fdULL, 0x9b7d1453c8d0711aULL,
			  0x32615fd6de46db91ULL },
			{ 0xb63fd, 0x8711a, 0xedb91 },
		}, {
			0x80000, 1, 2,
			{ 0xe258a957ab5c7ffbULL, 0x0d16d7949ea22ad2ULL,
			  0xcbd601717a3ed867ULL },
			{ 0xc7ffb, 0xa2ad2, 0xed867 },
		}, {
			0xfffffffff, 0x123456789abcdef0ULL, 0xfedcba9876543210ULL,
			{ 0xa0888cfc71c78784ULL, 0xdff18462edf3afffULL,
			  0x69f81059d3c96787ULL },
			{ 0xf8784, 0xbafff, 0x96787 },
		}, {
			0x7ffffff, 0x123456789abcdef0ULL, 0xfedcba9876543210ULL,
			{ 0x6672ceec955ab347ULL, 0x308558bf2437f9bfULL,
			  0x26aae7943f162d18ULL },
			{ 0xab347, 0xff9bf, 0xe2d18 },
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		u64 base = revelator_hash_base(vectors[i].x, vectors[i].id,
					       vectors[i].secret);

		for (unsigned int j = 0; j < ARRAY_SIZE(vectors[i].hashes); j++) {
			u64 hash = revelator_hash_seed(base, j + 1);

			KUNIT_EXPECT_EQ(test, hash, vectors[i].hashes[j]);
			KUNIT_EXPECT_EQ(test, revelator_pfn(hash), vectors[i].pfns[j]);
		}
	}
}

static unsigned long candidate_pa(unsigned long va, bool table, u64 id, u64 secret)
{
	u64 base = revelator_hash_base(revelator_key(va, table), id, secret);
	unsigned long pfn = revelator_pfn(revelator_hash_seed(base, 1));
	unsigned long offset;

	if (table)
		offset = (revelator_vpn(va) & (PTRS_PER_PTE - 1)) * sizeof(pte_t);
	else
		offset = offset_in_page(va);
	return PFN_PHYS(pfn) + offset;
}

static void revelator_sv48_addresses(struct kunit *test)
{
	const unsigned long va = 0x10000000000UL;
	const u64 id = 0x123456789abcdef0ULL;
	const u64 secret = 0xfedcba9876543210ULL;

	KUNIT_EXPECT_EQ(test, candidate_pa(va, false, 1, 2), 0xb63fd000UL);
	KUNIT_EXPECT_EQ(test, candidate_pa(va + 4095, false, 1, 2), 0xb63fdfffUL);
	KUNIT_EXPECT_EQ(test, candidate_pa(va, true, 1, 2), 0xc7ffb000UL);
	KUNIT_EXPECT_EQ(test, candidate_pa(va + SZ_2M - 1, true, 1, 2), 0xc7ffbff8UL);
	KUNIT_EXPECT_EQ(test, revelator_key(va + SZ_2M, true), 0x80001ULL);
	KUNIT_EXPECT_EQ(test, candidate_pa(va + SZ_2M, true, 1, 2), 0xa5002000UL);
	KUNIT_EXPECT_EQ(test, candidate_pa(~0UL, false, id, secret), 0xf8784fffUL);
	KUNIT_EXPECT_EQ(test, candidate_pa(~0UL, true, id, secret), 0xab347ff8UL);
}

static struct kunit_case revelator_hash_cases[] = {
	KUNIT_CASE(revelator_hash_vectors),
	KUNIT_CASE(revelator_sv48_addresses),
	{ }
};

static struct kunit_suite revelator_hash_suite = {
	.name = "revelator_hash",
	.test_cases = revelator_hash_cases,
};
kunit_test_suite(revelator_hash_suite);

MODULE_LICENSE("GPL");

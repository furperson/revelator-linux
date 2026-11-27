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
static void revelator_compact_vectors(struct kunit *test)
{
	static const struct {
		u64 x;
		u64 id;
		u64 secret;
		u64 mix13[3];
		u64 multiply_shift[3];
	} vectors[] = {
		{
			0, 0, 0,
			{ 0xe220a8397b1dcdafULL, 0x6e789e6aa1b965f4ULL,
			  0x06c45d188009454fULL },
			{ 0x105deULL, 0x20bbdULL, 0x3119bULL },
		}, {
			0x10000000, 1, 2,
			{ 0xb4f30eefaf3d8476ULL, 0x740d9a7556b162d5ULL,
			  0xfd210a2b08c45481ULL },
			{ 0x1c2b5ULL, 0x2c894ULL, 0x3ce72ULL },
		}, {
			0x80000, 1, 2,
			{ 0xabdd2e8dbb70c28aULL, 0x98f9bd7c3b7cdc40ULL,
			  0x522cd1ac5ae2cf09ULL },
			{ 0x13fbULL, 0x119d9ULL, 0x21fb8ULL },
		}, {
			0xfffffffffULL, 0x123456789abcdef0ULL,
			0xfedcba9876543210ULL,
			{ 0x04932a5575fda4e0ULL, 0x00a9395013f8df92ULL,
			  0xf8aa729a56e04b4dULL },
			{ 0x1c21fULL, 0x2c7feULL, 0x3cddcULL },
		}, {
			0x7ffffffULL, 0x123456789abcdef0ULL,
			0xfedcba9876543210ULL,
			{ 0x5424fd88f24401bULL, 0x3eaf11d961aa7edaULL,
			  0x6f95b0f2e5f77a30ULL },
			{ 0x3078bULL, 0x40d69ULL, 0x51348ULL },
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		for (unsigned int j = 0; j < 3; j++) {
			u64 mix13 = revelator_hash_compact(vectors[i].x, vectors[i].id,
							   vectors[i].secret, j + 1,
							   REVELATOR_HASH_MIX13);
			u64 multiply_shift =
				revelator_hash_compact(vectors[i].x, vectors[i].id,
						       vectors[i].secret, j + 1,
						       REVELATOR_HASH_MULTIPLY_SHIFT);

			KUNIT_EXPECT_EQ(test, mix13, vectors[i].mix13[j]);
			KUNIT_EXPECT_EQ(test, multiply_shift,
					vectors[i].multiply_shift[j]);
			KUNIT_EXPECT_EQ(test, revelator_pfn(mix13),
					REVELATOR_PFN_BASE +
					(vectors[i].mix13[j] &
					 (REVELATOR_PFN_COUNT - 1)));
			KUNIT_EXPECT_EQ(test, revelator_pfn(multiply_shift),
					REVELATOR_PFN_BASE +
					(vectors[i].multiply_shift[j] &
					 (REVELATOR_PFN_COUNT - 1)));
		}
	}

	KUNIT_EXPECT_EQ(test, PFN_PHYS(revelator_pfn(
				revelator_hash_compact(0x10000000, 1, 2, 1,
						       REVELATOR_HASH_MIX13))),
			0xd8476000UL);
	KUNIT_EXPECT_EQ(test, PFN_PHYS(revelator_pfn(
				revelator_hash_compact(0x10000000, 1, 2, 1,
						       REVELATOR_HASH_MULTIPLY_SHIFT))),
			0x9c2b5000UL);
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
	KUNIT_CASE(revelator_compact_vectors),
	KUNIT_CASE(revelator_sv48_addresses),
	{ }
};

static struct kunit_suite revelator_hash_suite = {
	.name = "revelator_hash",
	.test_cases = revelator_hash_cases,
};
kunit_test_suite(revelator_hash_suite);

MODULE_LICENSE("GPL");

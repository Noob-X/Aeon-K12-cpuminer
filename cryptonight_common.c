// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/KangarooTwelve.h"

#if defined __unix__ && (!defined __APPLE__)
#include <sys/mman.h>
#elif defined _WIN32
#include <windows.h>
#endif

void k12(char *hash, const void *data, size_t length)
{
	KangarooTwelve((const unsigned char *)data, length, (unsigned char *)hash, 32, 0, 0);
}

void k12_hash(void* output, const void* input, size_t len)
{
	k12(output, input, len);
}

int scanhash_k12(int thr_id, uint32_t *restrict pdata, int dlen, const uint64_t *restrict ptarget,
			 uint64_t max_nonce, uint64_t *restrict hashes_done)
{
	uint64_t *nonceptr = (uint64_t*) (((char*)pdata) + 39);
	uint64_t n = *nonceptr - 1;
	const uint64_t first_nonce = n + 1;

	const uint64_t Htarg = ptarget[7];
	uint64_t hash[32 / 8] __attribute__((aligned(64)));
	
	do {
		*nonceptr = ++n;
		k12((char *)hash, pdata, dlen);
		if (unlikely(hash[3] < Htarg)) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
//printf("n is %"PRIu64"\n", n);
//printf("first nonce is %"PRIu64"\n", first_nonce);
	*hashes_done = n - first_nonce + 1;
	return 0;
}

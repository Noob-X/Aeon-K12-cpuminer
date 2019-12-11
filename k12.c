// K12 CPU miner implementation Copyright (c) 2019 Wolf9466 (AKA Wolf0/OhGodAPet)

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//    This product includes software developed by Wolf9466.
// 4. Neither the name of the <organization> nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ''AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "cpuminer-config.h"
#include "miner.h"

#include <stdint.h>
#include <string.h>

#define ROTL64(x, n)		(((x) << (n)) | ((x) >> (64 - (n))))

const uint64_t KeccakF1600RndConsts[12] =
{
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

void KeccakF1600(uint64_t *st, const uint64_t RndConst)
{
	uint64_t bc[5], tmp;

	// Theta
	bc[0] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24] ^ ROTL64(st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21], 1);
	bc[1] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20] ^ ROTL64(st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22], 1);
	bc[2] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21] ^ ROTL64(st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23], 1);
	bc[3] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22] ^ ROTL64(st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24], 1);
	bc[4] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23] ^ ROTL64(st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20], 1);
	st[0] ^= bc[0];

	// Rho & Pi
	tmp = ROTL64(st[ 1] ^ bc[1], 1);
	st[ 1] = ROTL64(st[ 6] ^ bc[1], 44);
	st[ 6] = ROTL64(st[ 9] ^ bc[4], 20);
	st[ 9] = ROTL64(st[22] ^ bc[2], 61);
	st[22] = ROTL64(st[14] ^ bc[4], 39);
	st[14] = ROTL64(st[20] ^ bc[0], 18);
	st[20] = ROTL64(st[ 2] ^ bc[2], 62);
	st[ 2] = ROTL64(st[12] ^ bc[2], 43);
	st[12] = ROTL64(st[13] ^ bc[3], 25);
	st[13] = ROTL64(st[19] ^ bc[4],  8);
	st[19] = ROTL64(st[23] ^ bc[3], 56);
	st[23] = ROTL64(st[15] ^ bc[0], 41);
	st[15] = ROTL64(st[ 4] ^ bc[4], 27);
	st[ 4] = ROTL64(st[24] ^ bc[4], 14);
	st[24] = ROTL64(st[21] ^ bc[1],  2);
	st[21] = ROTL64(st[ 8] ^ bc[3], 55);
	st[ 8] = ROTL64(st[16] ^ bc[1], 45);
	st[16] = ROTL64(st[ 5] ^ bc[0], 36);
	st[ 5] = ROTL64(st[ 3] ^ bc[3], 28);
	st[ 3] = ROTL64(st[18] ^ bc[3], 21);
	st[18] = ROTL64(st[17] ^ bc[2], 15);
	st[17] = ROTL64(st[11] ^ bc[1], 10);
	st[11] = ROTL64(st[ 7] ^ bc[2],  6);
	st[ 7] = ROTL64(st[10] ^ bc[0],  3);
	st[10] = tmp;

	// Chi
	bc[0] = st[ 0]; bc[1] = st[ 1]; st[ 0] ^= (~bc[1]) & st[ 2]; st[ 1] ^= (~st[ 2]) & st[ 3]; st[ 2] ^= (~st[ 3]) & st[ 4]; st[ 3] ^= (~st[ 4]) & bc[0]; st[ 4] ^= (~bc[0]) & bc[1];
	bc[0] = st[ 5]; bc[1] = st[ 6]; st[ 5] ^= (~bc[1]) & st[ 7]; st[ 6] ^= (~st[ 7]) & st[ 8]; st[ 7] ^= (~st[ 8]) & st[ 9]; st[ 8] ^= (~st[ 9]) & bc[0]; st[ 9] ^= (~bc[0]) & bc[1];
	bc[0] = st[10]; bc[1] = st[11]; st[10] ^= (~bc[1]) & st[12]; st[11] ^= (~st[12]) & st[13]; st[12] ^= (~st[13]) & st[14]; st[13] ^= (~st[14]) & bc[0]; st[14] ^= (~bc[0]) & bc[1];
	bc[0] = st[15]; bc[1] = st[16]; st[15] ^= (~bc[1]) & st[17]; st[16] ^= (~st[17]) & st[18]; st[17] ^= (~st[18]) & st[19]; st[18] ^= (~st[19]) & bc[0]; st[19] ^= (~bc[0]) & bc[1];
	bc[0] = st[20]; bc[1] = st[21]; st[20] ^= (~bc[1]) & st[22]; st[21] ^= (~st[22]) & st[23]; st[22] ^= (~st[23]) & st[24]; st[23] ^= (~st[24]) & bc[0]; st[24] ^= (~bc[0]) & bc[1];

	// Iota
	st[0] ^= RndConst;
}

uint64_t k12_PoW(const void *input, int dlen)
{
	uint64_t st[25] __attribute__((aligned(64)));
	uint64_t tmp0, tmp3, tmp4;

	memset(st, 0x00, 200);
	memcpy(st, input, dlen);

	// Padding
	((uint8_t *)st)[dlen + 1] = 0x07;
	st[20] = 0x8000000000000000ULL;

	for(int i = 0; i < 11; ++i) KeccakF1600(st, KeccakF1600RndConsts[i]);

	tmp0 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24] ^ ROTL64(st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21], 1);
	tmp3 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22] ^ ROTL64(st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24], 1);
	tmp4 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23] ^ ROTL64(st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20], 1);

	tmp0 ^= st[0];
	tmp3 = ROTL64(st[18] ^ tmp3, 21);
	tmp4 = ROTL64(st[24] ^ tmp4, 14);

	return(tmp3 ^ ((~tmp4) & tmp0));
}

void k12_hash(void *output, const void *input, int dlen)
{
	uint64_t st[25] __attribute__((aligned(64)));

	memset(st, 0x00, 200);
	memcpy(st, input, dlen);

	// Padding
	((uint8_t *)st)[dlen + 1] = 0x07;
	st[20] = 0x8000000000000000ULL;

	for(int i = 0; i < 12; ++i) KeccakF1600(st, KeccakF1600RndConsts[i]);
	memcpy(output, st, 32);
}

int scanhash_k12(int thr_id, uint32_t *restrict pdata, int dlen, const uint64_t *restrict ptarget,
			 uint64_t max_nonce, uint64_t *restrict hashes_done)
{
	uint64_t *nonceptr = (uint64_t*) (((char*)pdata) + 39);
	uint64_t n = *nonceptr - 1;
	const uint64_t first_nonce = n + 1;
	const uint64_t Htarg = ptarget[7];

	do
	{
		*nonceptr = ++n;
		uint64_t qword3 = k12_PoW(pdata, dlen);
		if(unlikely(qword3 < Htarg))
		{
			*hashes_done = n - first_nonce + 1;
			return(1);
		}
	} while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
	*hashes_done = n - first_nonce + 1;

	return(0);
}

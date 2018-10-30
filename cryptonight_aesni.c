#include <x86intrin.h>
#include "cryptonight.h"
#include <string.h>
#include "mul128.h"

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
	__m128i tmp4;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
	tmp4 = _mm_slli_si128(*tmp1, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
	__m128i tmp2, tmp4;
	
	tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
	tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
	tmp4 = _mm_slli_si128(*tmp3, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	*tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static inline void ExpandAESKey256(const __m128i *userkey, __m128i *keys)
{
	__m128i tmp1, tmp2, tmp3;
	
	tmp1 = userkey[0];
	tmp3 = userkey[1];

	keys[0] = tmp1;
	keys[1] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[2] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[3] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[4] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[5] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[6] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[7] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[8] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[9] = tmp3;
}

void cryptonight_hash_ctx(void *restrict output, const void *restrict input, struct cryptonight_ctx *restrict ctx)
{
	keccak((const uint8_t *)input, 76, &ctx->state.hs.b[0], 200);

	/* POW change */
	const uint64_t tweak1_2 = ctx->state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER));
	/* end of POW change */

	size_t i;
	__m128i ukey[2], expkey[10];

	ukey[0] = ctx->state.hs.v[0];
	ukey[1] = ctx->state.hs.v[1];

	ExpandAESKey256(ukey, expkey);

	__m128i *longoutput;

	longoutput = (__m128i *)&ctx->long_state;

			ctx->text[0] = _mm_aesenc_si128(ctx->state.hs.v[4], expkey[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

			ctx->text[1] = _mm_aesenc_si128(ctx->state.hs.v[5], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

			ctx->text[2] = _mm_aesenc_si128(ctx->state.hs.v[6], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

			ctx->text[3] = _mm_aesenc_si128(ctx->state.hs.v[7], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[1]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[2]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[4]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[5]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[6]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[8]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);

		_mm_store_si128(&(longoutput[0]), ctx->text[0]);
		_mm_store_si128(&(longoutput[1]), ctx->text[1]);
		_mm_store_si128(&(longoutput[2]), ctx->text[2]);
		_mm_store_si128(&(longoutput[3]), ctx->text[3]);

			ctx->text[4] = _mm_aesenc_si128(ctx->state.hs.v[8], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

			ctx->text[5] = _mm_aesenc_si128(ctx->state.hs.v[9], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

			ctx->text[6] = _mm_aesenc_si128(ctx->state.hs.v[10], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

			ctx->text[7] = _mm_aesenc_si128(ctx->state.hs.v[11], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[1]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[2]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[3]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[4]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[5]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[6]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[8]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);

		_mm_store_si128(&(longoutput[4]), ctx->text[4]);
		_mm_store_si128(&(longoutput[5]), ctx->text[5]);
		_mm_store_si128(&(longoutput[6]), ctx->text[6]);
		_mm_store_si128(&(longoutput[7]), ctx->text[7]);

    for (i = INIT_SIZE_BYTE; __builtin_expect(i < MEMORY, 1); i += INIT_SIZE_BYTE)
    {
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[1]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[2]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[4]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[5]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[6]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[8]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);

		_mm_store_si128(&(longoutput[(i >> 4)]), ctx->text[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), ctx->text[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), ctx->text[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), ctx->text[3]);

			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[1]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[2]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[3]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[4]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[5]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[6]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[8]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);

		_mm_store_si128(&(longoutput[(i >> 4) + 4]), ctx->text[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), ctx->text[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), ctx->text[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), ctx->text[7]);
    }
#if 1
	uint64_t a[2] __attribute((aligned(16)));
	uint64_t b[2] __attribute((aligned(16)));

	__m128i *av = (__m128i *)&a;
	__m128i *bv = (__m128i *)&b;

	ukey[0] = ctx->state.hs.v[2];
	ukey[1] = ctx->state.hs.v[3];

	*av = _mm_xor_si128(expkey[0], ukey[0]);
	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);
	*bv = _mm_xor_si128(expkey[1], ukey[1]);

// start
	uint64_t c[2] __attribute((aligned(16)));
	__m128i *cv = (__m128i *)&c;

	*cv = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
	*cv = _mm_aesenc_si128(*cv, *av);

	__builtin_prefetch(&ctx->long_state[c[0] & 0x1FFFF0], 0, 1);

	*bv = _mm_xor_si128(*bv, *cv);
	/* POW change */
	uint8_t pow_tmp = _mm_extract_epi8(*bv, 11);
	static const uint32_t table = 0x75310;
	uint8_t index = (((pow_tmp >> 3) & 6) | (pow_tmp & 1)) << 1;
	pow_tmp = pow_tmp ^ ((table >> index) & 0x30);
	*bv = _mm_insert_epi8(*bv, pow_tmp, 11);
	/* end of POW change */
	_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], *bv);
	*bv = _mm_load_si128((__m128i *)&ctx->long_state[c[0] & 0x1FFFF0]);

	/* 64bit multiply of c[0] and b[0] */
	uint64_t hi, lo = mul128(c[0], b[0], &hi);

	a[0] += hi;
	a[1] += lo;

	uint64_t *dst1 = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
	dst1[0] = a[0];
	/* POW change */
	dst1[1] = a[1] ^ tweak1_2;
	/* end of POW change */

	a[0] ^= b[0];
	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);
	a[1] ^= b[1];

	*bv = *cv;

//second

	*cv = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
	*cv = _mm_aesenc_si128(*cv, *av);
	__builtin_prefetch(&ctx->long_state[c[0] & 0x1FFFF0], 0, 1);

	*bv = _mm_xor_si128(*bv, *cv);
	/* POW change */
	pow_tmp = _mm_extract_epi8(*bv, 11);
	index = (((pow_tmp >> 3) & 6) | (pow_tmp & 1)) << 1;
	pow_tmp = pow_tmp ^ ((table >> index) & 0x30);
	*bv = _mm_insert_epi8(*bv, pow_tmp, 11);
	/* end of POW change */
	_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], *bv);
	*bv = _mm_load_si128((__m128i *)&ctx->long_state[c[0] & 0x1FFFF0]);

	/* 64bit multiply of c[0] and b[0] */
	lo = mul128(c[0], b[0], &hi);

	a[0] += hi;
	a[1] += lo;

	uint64_t *dst2 = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
	dst2[0] = a[0];
	/* POW change */
	dst2[1] = a[1] ^ tweak1_2;
	/* end of POW change */

	a[0] ^= b[0];
	a[1] ^= b[1];

	*bv = *cv;

	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);

	for(i = 2; __builtin_expect(i < 0x80000, 1); i++)
	{
	*cv = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
	*cv = _mm_aesenc_si128(*cv, *av);

	__builtin_prefetch(&ctx->long_state[c[0] & 0x1FFFF0], 0, 1);

	*bv = _mm_xor_si128(*bv, *cv);
	/* POW change */
	pow_tmp = _mm_extract_epi8(*bv, 11);
	index = (((pow_tmp >> 3) & 6) | (pow_tmp & 1)) << 1;
	pow_tmp = pow_tmp ^ ((table >> index) & 0x30);
	*bv = _mm_insert_epi8(*bv, pow_tmp, 11);
	/* end of POW change */
	_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], *bv);
	*bv = _mm_load_si128((__m128i *)&ctx->long_state[c[0] & 0x1FFFF0]);

	/* 64bit multiply of c[0] and b[0] */
	lo = mul128(c[0], b[0], &hi);

	a[0] += hi;
	a[1] += lo;

	uint64_t *dst = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
	dst[0] = a[0];
	/* POW change */
	dst[1] = a[1] ^ tweak1_2;
	/* end of POW change */

	a[0] ^= b[0];
	a[1] ^= b[1];

	*bv = *cv;

	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);
	}
#else

	ukey[0] = ctx->state.hs.v[2];
	ukey[1] = ctx->state.hs.v[3];

	__m128i av = _mm_xor_si128(expkey[0], ukey[0]);
	__m128i bv = _mm_xor_si128(expkey[1], ukey[1]);

	__attribute((aligned(16))) uint64_t a0 = _mm_cvtsi128_si64(av);
	__attribute((aligned(16))) uint64_t idx_a = a0 & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_a], 0, 1);

	for(i = 0; __builtin_expect(i < 0x80000, 1); i++)
	{
	__m128i cv = _mm_load_si128((__m128i *)&ctx->long_state[idx_a]);
	cv = _mm_aesenc_si128(cv, av);

	__attribute((aligned(16))) uint64_t c0 = _mm_cvtsi128_si64(cv);
	__attribute((aligned(16))) uint64_t idx_c = c0 & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_c], 0, 1);

	bv = _mm_xor_si128(bv, cv);
	/* POW change */
	uint8_t pow_tmp = _mm_extract_epi8(bv, 11);
	static const uint32_t table = 0x75310;
	uint8_t index = (((pow_tmp >> 3) & 6) | (pow_tmp & 1)) << 1;
	pow_tmp = pow_tmp ^ ((table >> index) & 0x30);
	bv = _mm_insert_epi8(bv, pow_tmp, 11);
	/* end of POW change */
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a], bv);

	bv = _mm_load_si128((__m128i *)&ctx->long_state[idx_c]);
	__attribute((aligned(16))) uint64_t b0 = _mm_cvtsi128_si64(bv);

	/* 64bit multiply of c0 and b0 */
	__attribute((aligned(16))) uint64_t hi, lo = mul128(c0, b0, &hi);
	av += _mm_set_epi64x(lo, hi);
	/* POW change */
	__attribute((aligned(16))) uint64_t pow_temp2 = _mm_extract_epi64(av, 1);
	pow_temp2 ^= tweak1_2;
	__m128i pow_temp_v = _mm_insert_epi64(av, pow_temp2, 1);
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c], pow_temp_v);
	/* end of POW change */
	av = _mm_xor_si128(av, bv);

	bv = cv;

	a0 = _mm_cvtsi128_si64(av);
	idx_a = a0 & 0x1FFFF0;
	__builtin_prefetch(&idx_a, 0, 1);
	__builtin_prefetch(&ctx->long_state[idx_a], 0, 1);
	}
#endif
	ExpandAESKey256(ukey, expkey);
    
		ctx->text[0] = _mm_xor_si128(longoutput[0], ctx->state.hs.v[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

		ctx->text[1] = _mm_xor_si128(longoutput[1], ctx->state.hs.v[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

		ctx->text[2] = _mm_xor_si128(longoutput[2], ctx->state.hs.v[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

		ctx->text[3] = _mm_xor_si128(longoutput[3], ctx->state.hs.v[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[1]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[2]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[4]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[5]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[6]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[8]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);

		ctx->text[4] = _mm_xor_si128(longoutput[4], ctx->state.hs.v[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

		ctx->text[5] = _mm_xor_si128(longoutput[5], ctx->state.hs.v[9]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

		ctx->text[6] = _mm_xor_si128(longoutput[6], ctx->state.hs.v[10]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

		ctx->text[7] = _mm_xor_si128(longoutput[7], ctx->state.hs.v[11]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[1]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[2]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[3]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[4]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[5]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[6]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[8]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);

    for (i = INIT_SIZE_BYTE; __builtin_expect(i < (MEMORY - INIT_SIZE_BYTE), 1); i += INIT_SIZE_BYTE)
	{
		ctx->text[0] = _mm_xor_si128(longoutput[(i >> 4)], ctx->text[0]);
		ctx->text[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], ctx->text[1]);
		ctx->text[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], ctx->text[2]);
		ctx->text[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], ctx->text[3]);
		ctx->text[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], ctx->text[4]);
		ctx->text[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], ctx->text[5]);
		ctx->text[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], ctx->text[6]);
		ctx->text[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], ctx->text[7]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[0]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[1]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[2]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[3]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[4]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[5]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[6]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[7]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[8]);

			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);
	}
// exit
		ctx->text[0] = _mm_xor_si128(longoutput[131064], ctx->text[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);

			ctx->state.hs.v[4] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

		ctx->text[1] = _mm_xor_si128(longoutput[131065], ctx->text[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);

			ctx->state.hs.v[5] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

		ctx->text[2] = _mm_xor_si128(longoutput[131066], ctx->text[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);

			ctx->state.hs.v[6] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

		ctx->text[3] = _mm_xor_si128(longoutput[131067], ctx->text[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[1]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[2]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[3]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[4]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[5]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[6]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[7]);
			ctx->text[3] = _mm_aesenc_si128(ctx->text[3], expkey[8]);

			ctx->state.hs.v[7] = _mm_aesenc_si128(ctx->text[3], expkey[9]);

		ctx->text[4] = _mm_xor_si128(longoutput[131068], ctx->text[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);

			ctx->state.hs.v[8] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

		ctx->text[5] = _mm_xor_si128(longoutput[131069], ctx->text[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);

			ctx->state.hs.v[9] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

		ctx->text[6] = _mm_xor_si128(longoutput[131070], ctx->text[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);

			ctx->state.hs.v[10] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

		ctx->text[7] = _mm_xor_si128(longoutput[131071], ctx->text[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[1]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[2]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[3]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[4]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[5]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[6]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[7]);
			ctx->text[7] = _mm_aesenc_si128(ctx->text[7], expkey[8]);

			ctx->state.hs.v[11] = _mm_aesenc_si128(ctx->text[7], expkey[9]);

	keccakf(&ctx->state.hs.w[0], 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}

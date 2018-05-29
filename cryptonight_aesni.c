#include <x86intrin.h>
#include "cryptonight.h"
#include <string.h>
#include "mul128.h"

// void aesni_parallel_noxor(uint8_t *long_state, uint8_t *text, uint8_t *ExpandedKey);
// void aesni_parallel_xor(uint8_t *text, uint8_t *ExpandedKey, uint8_t *long_state);
// void that_fucking_loop(uint8_t a[16], uint8_t b[16], uint8_t *long_state);

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
//static inline void ExpandAESKey256(uint8_t *keybuf)
static inline void ExpandAESKey256(const __m128i *userkey, __m128i *keys)
//static inline void ExpandAESKey256(__m128i *keys)
{
	__m128i tmp1, tmp2, tmp3;
	
//	__m128i *keys = keybuf;
	
//	tmp1 = _mm_load_si128((__m128i *)userkey);
//	tmp3 = _mm_load_si128((__m128i *)(userkey+0x10));

	tmp1 = userkey[0];
	tmp3 = userkey[1];

//	tmp1 = keys[0];
//	tmp3 = keys[1];

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
/*
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[10] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[11] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[12] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[13] = tmp3;
	
	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[14] = tmp1;
*/
}

void cryptonight_hash_ctx(void *restrict output, const void *restrict input, struct cryptonight_ctx *restrict ctx)
{
	keccak((const uint8_t *)input, 76, &ctx->state.hs.b[0], 200);

	/* POW change */
	const uint64_t tweak1_2 = ctx->state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER));
	/* end of POW change */

//    uint8_t ExpandedKey[240];
//    size_t i, j;
	size_t i;
	__m128i ukey[2], expkey[10];
	__m128i *init_v;
	init_v = ctx->state.init;
    
//    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
//    memcpy(ExpandedKey, ctx->state.hs.b, AES_KEY_SIZE);
//	memcpy(ukey, ctx->state.hs.b, AES_KEY_SIZE);
//	ukey[0] = _mm_loadu_si128((__m128i *)&ctx->state.hs.b[0]);
//	ukey[1] = _mm_loadu_si128((__m128i *)&ctx->state.hs.b[16]);
//	ukey[0] = _mm_loadu_si128(&ctx->state.hs.v[0]);
//	ukey[1] = _mm_loadu_si128(&ctx->state.hs.v[1]);
	ukey[0] = ctx->state.hs.v[0];
	ukey[1] = ctx->state.hs.v[1];
//    ExpandAESKey256(ExpandedKey);
	ExpandAESKey256(ukey, expkey);
//    __m128i *longoutput, *expkey, *xmminput;
//	__m128i *longoutput, *xmminput;
	__m128i *longoutput;
//	__m128i xmminput[8];
	longoutput = (__m128i *)&ctx->long_state;
//	expkey = (__m128i *)ExpandedKey;
//	xmminput = (__m128i *)ctx->text;
//	xmminput = ctx->text;
//	memcpy(xmminput, ctx->text, INIT_SIZE_BYTE);
    
    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_noxor(&ctx->long_state[i], ctx->text, ExpandedKey);
/*
			ctx->text[0] = _mm_aesenc_si128(init_v[0], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(init_v[1], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(init_v[2], expkey[0]);
			ctx->text[3] = _mm_aesenc_si128(init_v[3], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(init_v[4], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(init_v[5], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(init_v[6], expkey[0]);
			ctx->text[7] = _mm_aesenc_si128(init_v[7], expkey[0]);

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

		_mm_store_si128(&(longoutput[(i >> 4)]), ctx->text[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), ctx->text[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), ctx->text[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), ctx->text[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), ctx->text[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), ctx->text[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), ctx->text[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), ctx->text[7]);
*/
			ctx->text[0] = _mm_aesenc_si128(init_v[0], expkey[0]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[1]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[2]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[3]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[4]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[5]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[6]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[7]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[8]);
			ctx->text[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

			ctx->text[1] = _mm_aesenc_si128(init_v[1], expkey[0]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[1]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[2]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[3]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[4]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[5]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[6]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[7]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[8]);
			ctx->text[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

			ctx->text[2] = _mm_aesenc_si128(init_v[2], expkey[0]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[1]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[2]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[3]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[4]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[5]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[6]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[7]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[8]);
			ctx->text[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

			ctx->text[3] = _mm_aesenc_si128(init_v[3], expkey[0]);
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

			ctx->text[4] = _mm_aesenc_si128(init_v[4], expkey[0]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[1]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[2]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[3]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[4]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[5]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[6]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[7]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[8]);
			ctx->text[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

			ctx->text[5] = _mm_aesenc_si128(init_v[5], expkey[0]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[1]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[2]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[3]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[4]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[5]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[6]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[7]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[8]);
			ctx->text[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

			ctx->text[6] = _mm_aesenc_si128(init_v[6], expkey[0]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[1]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[2]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[3]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[4]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[5]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[6]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[7]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[8]);
			ctx->text[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

			ctx->text[7] = _mm_aesenc_si128(init_v[7], expkey[0]);
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

//    for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
//    for (i = INIT_SIZE_BYTE; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    for (i = INIT_SIZE_BYTE; __builtin_expect(i < MEMORY, 1); i += INIT_SIZE_BYTE)
    {
/*
		for(j = 0; j < 2; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], uKey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], uKey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], uKey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], uKey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], uKey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], uKey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], uKey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], uKey[j]);
		}

		for(j = 2; j < 6; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

		for(j = 6; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

//		printf("%lu\n", i);
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[0]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[0]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[0]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[0]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[0]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[0]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[0]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[0]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[1]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[1]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[1]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[1]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[1]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[1]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[1]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[1]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[2]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[2]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[2]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[2]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[2]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[2]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[2]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[2]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[3]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[3]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[3]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[3]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[3]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[3]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[3]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[3]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[4]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[4]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[4]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[4]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[4]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[4]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[4]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[4]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[5]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[5]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[5]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[5]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[5]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[5]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[5]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[5]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[6]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[6]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[6]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[6]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[6]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[6]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[6]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[6]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[7]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[7]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[7]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[7]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[7]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[7]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[7]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[7]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[8]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[8]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[8]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[8]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[8]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[8]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[8]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[8]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[9]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[9]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[9]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[9]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[9]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[9]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[9]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[9]);

		_mm_store_si128(&(longoutput[(i >> 4)]), xmminput[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), xmminput[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), xmminput[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), xmminput[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), xmminput[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), xmminput[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), xmminput[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), xmminput[7]);
*/
//		memcpy(ctx->text, xmminput, INIT_SIZE_BYTE);
/*
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

		_mm_store_si128(&(longoutput[(i >> 4)]), ctx->text[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), ctx->text[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), ctx->text[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), ctx->text[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), ctx->text[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), ctx->text[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), ctx->text[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), ctx->text[7]);
*/
// __builtin_prefetch(&(longoutput[(i >> 4)]), 1, 1);
// __builtin_prefetch(&(ctx->long_state[(i >> 4)]), 1, 1);
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
// __builtin_prefetch(&(longoutput[(i >> 4) + 4]), 1, 1);
// __builtin_prefetch(&(ctx->long_state[(i >> 4) + 4]), 1, 1);
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

//	*av = _mm_xor_si128(expkey[0], ctx->state.hs.v[2]);
//	*bv = _mm_xor_si128(expkey[1], ctx->state.hs.v[3]);

	*av = _mm_xor_si128(expkey[0], ukey[0]);
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
//	dst1[1] = a[1];
	/* end of POW change */

	a[0] ^= b[0];

	a[1] ^= b[1];

	*bv = *cv;

	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);

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
//	dst2[1] = a[1];
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
//	dst[1] = a[1];
	/* end of POW change */

	a[0] ^= b[0];
	a[1] ^= b[1];

	*bv = *cv;

	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 1);
	}
#else
	__m128i av = _mm_xor_si128(expkey[0], ctx->state.hs.v[2]);
	__m128i bv = _mm_xor_si128(expkey[1], ctx->state.hs.v[3]);

	uint64_t ac0 = _mm_cvtsi128_si64(av);
	uint64_t idx_a = ac0 & 0x1FFFF0;

	for(i = 0; __builtin_expect(i < 0x80000, 1); i++)
	{
	__m128i cv = _mm_load_si128((__m128i *)&ctx->long_state[idx_a]);
	cv = _mm_aesenc_si128(cv, av);

	ac0 = _mm_cvtsi128_si64(cv);
	uint64_t idx_c = ac0 & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_c], 1, 1);

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
	idx_a = _mm_cvtsi128_si64(bv);

	/* 64bit multiply of ac0 and idx_a */
	uint64_t hi, lo = mul128(ac0, idx_a, &hi);
	av += _mm_set_epi64x(lo, hi);
	/* POW change */
	uint64_t pow_temp2 = _mm_extract_epi64(av, 1);
	pow_temp2 ^= tweak1_2;
	av = _mm_insert_epi64(av, pow_temp2, 1);
	/* end of POW change */
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c], av);
	av = _mm_xor_si128(av, bv);

	bv = cv;

	ac0 = _mm_cvtsi128_si64(av);
	idx_a = ac0 & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_a], 1, 3);
	}
#endif
//    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
//	__m128i *init_v2 = ctx->state.init;
//	memcpy(xmminput, ctx->text, INIT_SIZE_BYTE);
//    memcpy(ExpandedKey, &ctx->state.hs.b[32], AES_KEY_SIZE);
//    ExpandAESKey256(ExpandedKey);
//	memcpy(ukey, &ctx->state.hs.b[32], AES_KEY_SIZE);
//	ukey[0] = _mm_loadu_si128((__m128i *)&ctx->state.hs.b[32]);
//	ukey[1] = _mm_loadu_si128((__m128i *)&ctx->state.hs.b[48]);
//	ukey[0] = _mm_load_si128(&ctx->state.hs.v[2]);
//	ukey[1] = _mm_load_si128(&ctx->state.hs.v[3]);
//	ukey[0] = ctx->state.hs.v[2];
//	ukey[1] = ctx->state.hs.v[3];
	ExpandAESKey256(ukey, expkey);
    
    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_xor(&ctx->text, ExpandedKey, &ctx->long_state[i]);
/*
		ctx->text[0] = _mm_xor_si128(longoutput[0], init_v[0]);
		ctx->text[1] = _mm_xor_si128(longoutput[1], init_v[1]);
		ctx->text[2] = _mm_xor_si128(longoutput[2], init_v[2]);
		ctx->text[3] = _mm_xor_si128(longoutput[3], init_v[3]);
		ctx->text[4] = _mm_xor_si128(longoutput[4], init_v[4]);
		ctx->text[5] = _mm_xor_si128(longoutput[5], init_v[5]);
		ctx->text[6] = _mm_xor_si128(longoutput[6], init_v[6]);
		ctx->text[7] = _mm_xor_si128(longoutput[7], init_v[7]);

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
*/
		ctx->text[0] = _mm_xor_si128(longoutput[0], init_v[0]);
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

		ctx->text[1] = _mm_xor_si128(longoutput[1], init_v[1]);
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

		ctx->text[2] = _mm_xor_si128(longoutput[2], init_v[2]);
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

		ctx->text[3] = _mm_xor_si128(longoutput[3], init_v[3]);
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

		ctx->text[4] = _mm_xor_si128(longoutput[4], init_v[4]);
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

		ctx->text[5] = _mm_xor_si128(longoutput[5], init_v[5]);
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

		ctx->text[6] = _mm_xor_si128(longoutput[6], init_v[6]);
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

		ctx->text[7] = _mm_xor_si128(longoutput[7], init_v[7]);
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

//    for (i = 0; __builtin_expect(i < MEMORY, 1); i += INIT_SIZE_BYTE)
//    for (i = INIT_SIZE_BYTE; __builtin_expect(i < MEMORY, 1); i += INIT_SIZE_BYTE)
    for (i = INIT_SIZE_BYTE; __builtin_expect(i < (MEMORY - INIT_SIZE_BYTE), 1); i += INIT_SIZE_BYTE)
	{
/*
		xmminput[0] = _mm_xor_si128(longoutput[(i >> 4)], xmminput[0]);
		xmminput[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], xmminput[1]);
		xmminput[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], xmminput[2]);
		xmminput[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], xmminput[3]);
		xmminput[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], xmminput[4]);
		xmminput[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], xmminput[5]);
		xmminput[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], xmminput[6]);
		xmminput[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], xmminput[7]);
*/

		ctx->text[0] = _mm_xor_si128(longoutput[(i >> 4)], ctx->text[0]);
		ctx->text[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], ctx->text[1]);
		ctx->text[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], ctx->text[2]);
		ctx->text[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], ctx->text[3]);
		ctx->text[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], ctx->text[4]);
		ctx->text[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], ctx->text[5]);
		ctx->text[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], ctx->text[6]);
		ctx->text[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], ctx->text[7]);

/*
		for(j = 0; j < 2; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], uKey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], uKey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], uKey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], uKey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], uKey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], uKey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], uKey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], uKey[j]);
		}

		for(j = 2; j < 6; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

		for(j = 6; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[0]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[0]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[0]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[0]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[0]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[0]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[0]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[0]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[1]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[1]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[1]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[1]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[1]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[1]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[1]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[1]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[2]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[2]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[2]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[2]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[2]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[2]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[2]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[2]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[3]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[3]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[3]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[3]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[3]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[3]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[3]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[3]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[4]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[4]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[4]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[4]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[4]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[4]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[4]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[4]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[5]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[5]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[5]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[5]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[5]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[5]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[5]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[5]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[6]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[6]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[6]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[6]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[6]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[6]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[6]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[6]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[7]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[7]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[7]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[7]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[7]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[7]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[7]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[7]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[8]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[8]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[8]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[8]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[8]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[8]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[8]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[8]);

			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[9]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[9]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[9]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[9]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[9]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[9]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[9]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[9]);
*/
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
/*
		ctx->text[0] = _mm_xor_si128(longoutput[131064], ctx->text[0]);
		ctx->text[1] = _mm_xor_si128(longoutput[131065], ctx->text[1]);
		ctx->text[2] = _mm_xor_si128(longoutput[131066], ctx->text[2]);
		ctx->text[3] = _mm_xor_si128(longoutput[131067], ctx->text[3]);
		ctx->text[4] = _mm_xor_si128(longoutput[131068], ctx->text[4]);
		ctx->text[5] = _mm_xor_si128(longoutput[131069], ctx->text[5]);
		ctx->text[6] = _mm_xor_si128(longoutput[131070], ctx->text[6]);
		ctx->text[7] = _mm_xor_si128(longoutput[131071], ctx->text[7]);

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

			init_v[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);
			init_v[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);
			init_v[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);
			init_v[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);
			init_v[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);
			init_v[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);
			init_v[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);
			init_v[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);
*/
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
			init_v[0] = _mm_aesenc_si128(ctx->text[0], expkey[9]);

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
			init_v[1] = _mm_aesenc_si128(ctx->text[1], expkey[9]);

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
			init_v[2] = _mm_aesenc_si128(ctx->text[2], expkey[9]);

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
			init_v[3] = _mm_aesenc_si128(ctx->text[3], expkey[9]);

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
			init_v[4] = _mm_aesenc_si128(ctx->text[4], expkey[9]);

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
			init_v[5] = _mm_aesenc_si128(ctx->text[5], expkey[9]);

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
			init_v[6] = _mm_aesenc_si128(ctx->text[6], expkey[9]);

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
			init_v[7] = _mm_aesenc_si128(ctx->text[7], expkey[9]);

//        memcpy(ctx->text, xmminput, INIT_SIZE_BYTE);
//    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	keccakf(&ctx->state.hs.w[0], 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}

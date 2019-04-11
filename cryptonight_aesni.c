#include <x86intrin.h>
#include <string.h>
#include "cryptonight.h"
#include "mul128.h"
#include "variant4_random_math.h"
#include "CryptonightR_JIT.h"

#if defined __unix__
#include <sys/mman.h>
#elif defined _WIN32
#include <windows.h>
#endif

THREADV v4_random_math_JIT_func hp_jitfunc = NULL;
THREADV uint8_t *hp_jitfunc_memory = NULL;
THREADV int hp_jitfunc_allocated = 0;

void alloc_jit_mem(void)
{
#if defined(_MSC_VER) || defined(__MINGW32__)
	hp_jitfunc_memory = (uint8_t *) VirtualAlloc(hp_jitfunc_memory, 4096 + 4095,
						     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
	defined(__DragonFly__) || defined(__NetBSD__)
	hp_jitfunc_memory = mmap(0, 4096 + 4095, PROT_READ | PROT_WRITE | PROT_EXEC,
				 MAP_PRIVATE | MAP_ANON, 0, 0);
#else
	hp_jitfunc_memory = mmap(0, 4096 + 4095, PROT_READ | PROT_WRITE | PROT_EXEC,
				 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
#endif
	if(hp_jitfunc_memory == MAP_FAILED)
		hp_jitfunc_memory = NULL;
#endif

	hp_jitfunc_allocated = 1;
	if (hp_jitfunc_memory == NULL)
	{
		hp_jitfunc_allocated = 0;
		hp_jitfunc_memory = malloc(4096 + 4095);
	}
	hp_jitfunc = (v4_random_math_JIT_func)((size_t)(hp_jitfunc_memory + 4095) & ~4095);

#if !(defined(_MSC_VER) || defined(__MINGW32__))
	mprotect(hp_jitfunc, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
}

void free_jit_mem(void)
{
	if(!hp_jitfunc_allocated)
		free(hp_jitfunc_memory);
	else
	{
#if defined(_MSC_VER) || defined(__MINGW32__)
		VirtualFree(hp_jitfunc_memory, 0, MEM_RELEASE);
#else
		munmap(hp_jitfunc_memory, 4096 + 4095);
#endif
	}

	hp_jitfunc = NULL;
	hp_jitfunc_memory = NULL;
	hp_jitfunc_allocated = 0;
}

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

void cryptonight_hash_ctx(void *restrict output, const void *restrict input, int inlen,
			  struct cryptonight_ctx *restrict ctx, uint64_t height)
{
	if (hp_jitfunc_memory == NULL)
		alloc_jit_mem();

	keccak((const uint8_t *)input, inlen, &ctx->state.hs.b[0], 200);

	/* Variant 4 */
	VARIANT4_RANDOM_MATH_INIT();
	/* end of Variant 4 */

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

	uint64_t a[2] __attribute((aligned(16)));
	uint64_t b[2] __attribute((aligned(16)));

	__m128i *av = (__m128i *)&a;
	__m128i *bv = (__m128i *)&b;

	ukey[0] = ctx->state.hs.v[2];
	ukey[1] = ctx->state.hs.v[3];

	/* Variant 2 */
	__m128i dv = _mm_xor_si128(ctx->state.hs.v[4], ctx->state.hs.v[5]);
	/* end of Variant 2 */

	*av = _mm_xor_si128(expkey[0], ukey[0]);
	uint64_t idx_a = a[0] & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_a - (idx_a & 63)], 0, 1);
	*bv = _mm_xor_si128(expkey[1], ukey[1]);

/* start */
	uint64_t c[2] __attribute((aligned(16)));
	__m128i *cv = (__m128i *)&c;

	__m128i	main_chunk = _mm_load_si128((__m128i *)&ctx->long_state[idx_a]);
	__m128i chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10]);
	__m128i chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20]);
	__m128i chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30]);

	main_chunk = _mm_aesenc_si128(main_chunk, *av);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20], _mm_add_epi64(chunk1, *bv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30], _mm_add_epi64(chunk2, *av));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
       /* End of Variant 4 */
	*cv = main_chunk;

	uint64_t idx_c = c[0] & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_c - (idx_c & 63)], 0, 1);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a], _mm_xor_si128(*bv, main_chunk));

	__m128i b_tmp = *bv;

	uint64_t *dst1 = (uint64_t *)&ctx->long_state[idx_c];
	b[0] = dst1[0];
	b[1] = dst1[1];

	/* Variant 4 */
	__m128i a_tmp = *av;
	VARIANT4_RANDOM_MATH(a, b, r, &b_tmp, &dv);
	/* End of Variant 4 */

	/* 64bit multiply of c[0] and b[0] */
	uint64_t hi, lo = mul128(c[0], b[0], &hi);

	chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10]);
	chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20]);
	chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30]);
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20], _mm_add_epi64(chunk1, b_tmp));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30], _mm_add_epi64(chunk2, a_tmp));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
	/* End of Variant 4 */

	a[0] += hi;
	a[1] += lo;

	dst1[0] = a[0];
	dst1[1] = a[1];

	a[0] ^= b[0];
	idx_a = a[0] & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_a - (idx_a & 63)], 0, 1);
	a[1] ^= b[1];

	dv = b_tmp;
	*bv = main_chunk;

/* second */

	main_chunk = _mm_load_si128((__m128i *)&ctx->long_state[idx_a]);
	chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10]);
	chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20]);
	chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30]);

	main_chunk = _mm_aesenc_si128(main_chunk, *av);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20], _mm_add_epi64(chunk1, *bv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30], _mm_add_epi64(chunk2, *av));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
	/* End of Variant 4 */

	*cv = main_chunk;

	idx_c = c[0] & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_c - (idx_c & 63)], 0, 1);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a], _mm_xor_si128(*bv, main_chunk));

	b_tmp = *bv;

	uint64_t *dst2 = (uint64_t *)&ctx->long_state[idx_c];
	b[0] = dst2[0];
	b[1] = dst2[1];

	/* Variant 4 */
	a_tmp = *av;
	VARIANT4_RANDOM_MATH(a, b, r, &b_tmp, &dv);
	/* End of Variant 4 */

	/* 64bit multiply of c[0] and b[0] */
	lo = mul128(c[0], b[0], &hi);

	chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10]);
	chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20]);
	chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30]);
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20], _mm_add_epi64(chunk1, b_tmp));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30], _mm_add_epi64(chunk2, a_tmp));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
	/* End of Variant 4 */

	a[0] += hi;
	a[1] += lo;

	dst2[0] = a[0];
	dst2[1] = a[1];

	a[0] ^= b[0];
	idx_a = a[0] & 0x1FFFF0;
	a[1] ^= b[1];

	dv = b_tmp;
	*bv = main_chunk;
	__builtin_prefetch(&ctx->long_state[idx_a - (idx_a & 63)], 0, 1);

	for(i = 2; __builtin_expect(i < 0x80000, 1); i++)
	{
	main_chunk = _mm_load_si128((__m128i *)&ctx->long_state[idx_a]);
	chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10]);
	chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20]);
	chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30]);

	main_chunk = _mm_aesenc_si128(main_chunk, *av);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x20], _mm_add_epi64(chunk1, *bv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_a ^ 0x30], _mm_add_epi64(chunk2, *av));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
	/* End of Variant 4 */

	*cv = main_chunk;

	idx_c = c[0] & 0x1FFFF0;
	__builtin_prefetch(&ctx->long_state[idx_c - (idx_c & 63)], 0, 1);

	_mm_store_si128((__m128i *)&ctx->long_state[idx_a], _mm_xor_si128(*bv, main_chunk));

	b_tmp = *bv;

	uint64_t *dst = (uint64_t *)&ctx->long_state[idx_c];
	b[0] = dst[0];
	b[1] = dst[1];

	/* Variant 4 */
	a_tmp = *av;
	VARIANT4_RANDOM_MATH(a, b, r, &b_tmp, &dv);
	/* End of Variant 4 */

	/* 64bit multiply of c[0] and b[0] */
	lo = mul128(c[0], b[0], &hi);

	chunk1 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10]);
	chunk2 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20]);
	chunk3 = _mm_load_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30]);
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x10], _mm_add_epi64(chunk3, dv));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x20], _mm_add_epi64(chunk1, b_tmp));
	_mm_store_si128((__m128i *)&ctx->long_state[idx_c ^ 0x30], _mm_add_epi64(chunk2, a_tmp));

	/* Variant 4 */
	chunk1 = _mm_xor_si128(chunk1, chunk2);
	main_chunk = _mm_xor_si128(main_chunk, chunk3);
	main_chunk = _mm_xor_si128(main_chunk, chunk1);
	/* End of Variant 4 */

	a[0] += hi;
	a[1] += lo;

	dst[0] = a[0];
	dst[1] = a[1];

	a[0] ^= b[0];
	idx_a = a[0] & 0x1FFFF0;
	a[1] ^= b[1];

	dv = b_tmp;
	*bv = main_chunk;
	__builtin_prefetch(&ctx->long_state[idx_a - (idx_a & 63)], 0, 1);
	}

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

	keccakf(&ctx->state.hs.w[0]);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);

	if (hp_jitfunc_memory)
		free_jit_mem();
}

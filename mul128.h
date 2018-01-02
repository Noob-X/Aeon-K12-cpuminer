#ifndef __MUL128_H__
#define __MUL128_H__

#include <stdint.h>

static inline uint64_t mul128(uint64_t a, uint64_t b, uint64_t *hi)
{
	uint64_t lo;

#if __x86_64__
	  __asm__ ("mulq %3\n\t"
	  : "=d" (*hi),
	"=a" (lo)
	  : "%a" (a),
	"rm" (b)
	  : "cc" );

#elif _WIN64
	lo = _umul128(a, b, &hi);

#else
	uint64_t a_lo = (uint64_t)(uint32_t)a;
	uint64_t a_hi = a >> 32;
	uint64_t b_lo = (uint64_t)(uint32_t)b;
	uint64_t b_hi = b >> 32;

	uint64_t p0 = a_lo * b_lo;
	uint64_t p1 = a_lo * b_hi;
	uint64_t p2 = a_hi * b_lo;
	uint64_t p3 = a_hi * b_hi;

	uint32_t cy = (uint32_t)(((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32);

	lo = p0 + (p1 << 32) + (p2 << 32);
	*hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;

#endif
	return lo;
}

#endif /* __MUL128_H__ */

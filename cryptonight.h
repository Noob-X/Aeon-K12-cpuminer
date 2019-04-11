#ifndef __CRYPTONIGHT_H_INCLUDED
#define __CRYPTONIGHT_H_INCLUDED

#include <stddef.h>
#include <x86intrin.h>
#include "crypto/oaes_lib.h"
#include "miner.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)	// 128

#if defined(_MSC_VER)
#define THREADV __declspec(thread)
#else
#define THREADV __thread
#endif

#if __x86_64__
#define JIT 1
#else
#define JIT 0
#endif

#pragma pack(push, 1)
union hash_state {
  uint8_t b[200];
  uint64_t w[25];
  __m128i v[12];
};
#pragma pack(pop)

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64] __attribute__((aligned(16)));
	__m128i init[8];
    };
};
#pragma pack(pop)

#ifdef USE_LOBOTOMIZED_AES

struct cryptonight_ctx {
    uint8_t long_state[MEMORY] __attribute((aligned(16)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t c[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
#if 1
    oaes_ctx* aes_ctx;
#endif
} __attribute__((__may_alias__));

#else

struct cryptonight_ctx {
	union cn_slow_hash_state state;
	__m128i text[8] __attribute((aligned(16)));
	uint8_t long_state[MEMORY] __attribute((aligned(16)));
};

#endif

void do_blake_hash(const void* input, size_t len, char* output);
void do_groestl_hash(const void* input, size_t len, char* output);
void do_jh_hash(const void* input, size_t len, char* output);
void do_skein_hash(const void* input, size_t len, char* output);
void xor_blocks_dst(const uint64_t *a, const uint64_t *b, uint8_t *dst);
void cryptonight_hash_ctx(void* output, const void* input, int inlen, struct cryptonight_ctx* ctx, uint64_t height);
void keccak(const uint8_t *in, int inlen, uint8_t *md, const int mdlen);
void keccakf(uint64_t st[25]);
extern void (* const extra_hashes[4])(const void *, size_t, char *);

#endif

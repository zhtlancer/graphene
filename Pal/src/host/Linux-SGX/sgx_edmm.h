
#ifndef SGX_EDMM_H
#define SGX_EDMM_H

#include <stdint.h>

#define PRINT_EDMM_MEM_STAT 1

/* EDMM memory stats */
struct edmm_mem_stat {
    uint64_t alloc_cnt;
    uint64_t alloc_size;
    uint64_t alloc_max_size;
    uint64_t free_cnt;
    uint64_t free_size;
    uint64_t freed_size;

    uint64_t runtime_size;
    uint64_t runtime_size_max;

    uint64_t edmm_alloc_cnt;
    uint64_t edmm_alloc_size;
    uint64_t edmm_alloc_max_size;
    uint64_t edmm_free_cnt;
    uint64_t edmm_free_size;
    uint64_t edmm_freed_size;

    uint64_t edmm_runtime_size;
    uint64_t edmm_runtime_size_max;
};


#define SGX_EDMM_MODE_MASK  (0xFUL)
#define SGX_EDMM_MODE_NONE  (0x0UL)
#define SGX_EDMM_MODE_NAIVE (0x1UL)
#define SGX_EDMM_MODE_DEMAND    (0x2UL)

static inline int is_sgx_edmm_mode(unsigned long mode, unsigned long test_mode) {
    return (mode & SGX_EDMM_MODE_MASK) == test_mode;
}

#define SGX_EDMM_MEMPOOL_MASK      (0xF0UL)
#define SGX_EDMM_MEMPOOL_NONE      (0x00UL)
#define SGX_EDMM_MEMPOOL_NOFREE    (0x10UL)
#define SGX_EDMM_MEMPOOL_BUDDY     (0x20UL)

static inline int is_sgx_edmm_mempool(unsigned long mode, unsigned long test_mode) {
    return (mode & SGX_EDMM_MEMPOOL_MASK) == test_mode;
}

#define SGX_EDMM_BATCH_MASK     (0xF00UL)
#define SGX_EDMM_BATCH_NONE     (0x000UL)
#define SGX_EDMM_BATCH_BITMAP   (0x100UL)
#define SGX_EDMM_BATCH_WS_TRAIN (0x400UL)
#define SGX_EDMM_BATCH_WS_USE   (0x800UL)

static inline int is_sgx_edmm_batch(unsigned long mode, unsigned long test_mode) {
    return (mode & SGX_EDMM_BATCH_MASK) == test_mode;
}

#define EDMM_BITMAP_SIZE (1024*1024)
#define EDMM_BATCH_SIZE (64)
#define PAGE_SHIFT (12)

#define EDMM_BITMAP_OFFSET(x) ((x) >> 6)
#define EDMM_BITMAP_BITMASK(x) (1UL << ((x)&0x3f))

static inline unsigned long edmm_bitmap_is_set(volatile unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(bitmap + EDMM_BITMAP_OFFSET(pg));

    return bit_val & EDMM_BITMAP_BITMASK(pg);
}

static inline void edmm_bitmap_set(unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(bitmap + EDMM_BITMAP_OFFSET(pg));

    bit_val |= EDMM_BITMAP_BITMASK(pg);

    *(bitmap + EDMM_BITMAP_OFFSET(pg)) = bit_val;
}

static inline void edmm_bitmap_clear(unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(unsigned long *)(bitmap + EDMM_BITMAP_OFFSET(pg));

    bit_val &= ~EDMM_BITMAP_BITMASK(pg);

    *(unsigned long *)(bitmap + EDMM_BITMAP_OFFSET(pg)) = bit_val;
}

#endif


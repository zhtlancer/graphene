
#ifndef SGX_EDMM_H
#define SGX_EDMM_H

#define SGX_EDMM_MODE_MASK  (0xFUL)
#define SGX_EDMM_MODE_NONE  (0x0UL)
#define SGX_EDMM_MODE_NAIVE (0x1UL)
#define SGX_EDMM_MODE_LAZY  (0x2UL)

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

#endif


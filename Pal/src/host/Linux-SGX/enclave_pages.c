#include "sgx_edmm.h"
#include "enclave_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "list.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"

#define PRINT_ENCLAVE_MEM_STAT 1

#if PRINT_ENCLAVE_MEM_STAT
/* Enclave memory stats */
uint64_t g_stats_alloc_cnt;
uint64_t g_stats_alloc_size;
uint64_t g_stats_alloc_max_size;
uint64_t g_stats_free_cnt;
uint64_t g_stats_free_size;
uint64_t g_stats_freed_size;

uint64_t g_stats_runtime_size;
uint64_t g_stats_runtime_size_max;

uint64_t g_stats_edmm_alloc_cnt;
uint64_t g_stats_edmm_alloc_size;
uint64_t g_stats_edmm_alloc_max_size;
uint64_t g_stats_edmm_free_cnt;
uint64_t g_stats_edmm_free_size;
uint64_t g_stats_edmm_freed_size;

uint64_t g_stats_edmm_runtime_size;
uint64_t g_stats_edmm_runtime_size_max;

static PAL_LOCK g_enclave_stats_lock = LOCK_INIT;
#endif


struct atomic_int g_allocated_pages;

static size_t g_page_size = PRESET_PAGESIZE;
static void* g_heap_bottom;
static void* g_heap_top;

static size_t g_pal_internal_mem_used = 0;

/* list of VMAs of used memory areas kept in DESCENDING order; note that preallocated PAL internal
 * memory relies on this descending order of allocations (from high addresses to low), see
 * _DkGetAvailableUserAddressRange() for more details */
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    void* bottom;
    void* top;
    bool is_pal_internal;
};
DEFINE_LISTP(heap_vma);

struct edmm_heap_range {
    void* addr;
    size_t size;
};

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
static PAL_LOCK g_heap_vma_lock = LOCK_INIT;

/* heap_vma objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_HEAP_VMAS 100000
/* TODO: Setting this as 64 to start with, but will need to revisit */
#define EDMM_HEAP_RANGE_CNT 64
static struct heap_vma g_heap_vma_pool[MAX_HEAP_VMAS];
static size_t g_heap_vma_num = 0;
static struct heap_vma* g_free_vma = NULL;

/* EDMM vma */
static LISTP_TYPE(heap_vma) g_edmm_vma_list = LISTP_INIT;
static PAL_LOCK g_edmm_vma_lock = LOCK_INIT;

#define MAX_EDMM_VMAS 100000
static struct heap_vma g_edmm_vma_pool[MAX_EDMM_VMAS];
static size_t g_edmm_vma_num = 0;
static struct heap_vma* g_free_edmm_vma = NULL;

/* returns uninitialized heap_vma, the caller is responsible for setting at least bottom/top */
static struct heap_vma* __alloc_edmm_vma(void) {
    assert(_DkInternalIsLocked(&g_edmm_vma_lock));

    if (g_free_edmm_vma) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_free_edmm_vma >= (uintptr_t)&g_edmm_vma_pool[0]);
        assert((uintptr_t)g_free_edmm_vma <= (uintptr_t)&g_edmm_vma_pool[MAX_HEAP_VMAS - 1]);

        struct heap_vma* ret = g_free_edmm_vma;
        g_free_edmm_vma = NULL;
        g_edmm_vma_num++;
        return ret;
    }

    /* FIXME: this loop may become perf bottleneck on large number of vma objects; however,
     * experiments show that this number typically does not exceed 20 (thanks to VMA merging) */
    for (size_t i = 0; i < MAX_EDMM_VMAS; i++) {
        if (!g_edmm_vma_pool[i].bottom && !g_edmm_vma_pool[i].top) {
            /* found empty slot in the pool, use it */
            g_edmm_vma_num++;
            return &g_edmm_vma_pool[i];
        }
    }

    return NULL;
}

static void __free_edmm_vma(struct heap_vma* vma) {
    assert(_DkInternalIsLocked(&g_edmm_vma_lock));
    assert((uintptr_t)vma >= (uintptr_t)&g_edmm_vma_pool[0]);
    assert((uintptr_t)vma <= (uintptr_t)&g_edmm_vma_pool[MAX_EDMM_VMAS - 1]);

    g_free_edmm_vma  = vma;
    vma->top    = 0;
    vma->bottom = 0;
    g_edmm_vma_num--;
}

/* returns uninitialized heap_vma, the caller is responsible for setting at least bottom/top */
static struct heap_vma* __alloc_vma(void) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));

    if (g_free_vma) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_free_vma >= (uintptr_t)&g_heap_vma_pool[0]);
        assert((uintptr_t)g_free_vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

        struct heap_vma* ret = g_free_vma;
        g_free_vma = NULL;
        g_heap_vma_num++;
        return ret;
    }

    /* FIXME: this loop may become perf bottleneck on large number of vma objects; however,
     * experiments show that this number typically does not exceed 20 (thanks to VMA merging) */
    for (size_t i = 0; i < MAX_HEAP_VMAS; i++) {
        if (!g_heap_vma_pool[i].bottom && !g_heap_vma_pool[i].top) {
            /* found empty slot in the pool, use it */
            g_heap_vma_num++;
            return &g_heap_vma_pool[i];
        }
    }

    return NULL;
}

static void __free_vma(struct heap_vma* vma) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));
    assert((uintptr_t)vma >= (uintptr_t)&g_heap_vma_pool[0]);
    assert((uintptr_t)vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

    g_free_vma  = vma;
    vma->top    = 0;
    vma->bottom = 0;
    g_heap_vma_num--;
}

int init_enclave_pages(void) {
    g_heap_bottom = g_pal_sec.heap_min;
    g_heap_top    = g_pal_sec.heap_max;
    return 0;
}

static void* edmm_create_vma_and_merge(void* addr, size_t size,
                                    struct heap_vma* vma_above) {
    assert(_DkInternalIsLocked(&g_edmm_vma_lock));
    assert(addr && size);

    /* find enclosing VMAs and check that pal-internal VMAs do not overlap with normal VMAs */
    struct heap_vma* vma_below;
    if (vma_above) {
        vma_below = LISTP_NEXT_ENTRY(vma_above, &g_edmm_vma_list, list);
    } else {
        /* no VMA above `addr`; VMA right below `addr` must be the first (highest-address) in list */
        vma_below = LISTP_FIRST_ENTRY(&g_edmm_vma_list, struct heap_vma, list);
    }

    /* create VMA with [addr, addr+size); in case of existing overlapping VMAs, the created VMA is
     * merged with them and the old VMAs are discarded, similar to mmap(MAX_FIXED) */
    struct heap_vma* vma = __alloc_edmm_vma();
    if (!vma)
        return NULL;
    vma->bottom          = addr;
    vma->top             = addr + size;

    /* how much memory was freed because [addr, addr + size) overlapped with VMAs */
    size_t freed = 0;

    /* Try to merge VMAs as an optimization:
     *   (1) start from `vma_above` and iterate through VMAs with higher-addresses for merges
     *   (2) start from `vma_below` and iterate through VMAs with lower-addresses for merges.
     * Note that we never merge normal VMAs with pal-internal VMAs. */
    while (vma_above && vma_above->bottom <= vma->top &&
           vma_above->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE)) {
            log_debug("Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                    vma_above->bottom, vma_above->top);
        }

        freed += vma_above->top - vma_above->bottom;
        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_edmm_vma_list, list);

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_edmm_vma_list, list);

        __free_edmm_vma(vma_above);
        vma_above = vma_above_above;
    }

    while (vma_below && vma_below->top >= vma->bottom &&
           vma_below->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
        if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE)) {
            log_debug("Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                    vma_below->bottom, vma_below->top);
        }

        freed += vma_below->top - vma_below->bottom;
        struct heap_vma* vma_below_below = LISTP_NEXT_ENTRY(vma_below, &g_edmm_vma_list, list);

        vma->bottom = MIN(vma_below->bottom, vma->bottom);
        vma->top    = MAX(vma_below->top, vma->top);
        LISTP_DEL(vma_below, &g_edmm_vma_list, list);

        __free_edmm_vma(vma_below);
        vma_below = vma_below_below;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, vma_above, &g_edmm_vma_list, list);
    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE)) {
        log_debug("Created vma %p-%p\n", vma->bottom, vma->top);
    }

    if (vma->bottom >= vma->top) {
        log_error("*** Bad memory bookkeeping: %p - %p ***\n", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    return addr;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
int free_edmm_page_range(void* start, size_t size) {
    void* addr = ALLOC_ALIGN_DOWN_PTR(start);
    void* end = (void*)((char*)addr + size);
    int ret = 0;

#if PRINT_ENCLAVE_MEM_STAT
    __atomic_add_fetch(&g_stats_edmm_free_cnt, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_stats_edmm_free_size, size, __ATOMIC_SEQ_CST);

    __atomic_sub_fetch(&g_stats_edmm_runtime_size, size, __ATOMIC_SEQ_CST);
#endif

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_TRIM | SGX_SECINFO_FLAGS_MODIFIED;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    size_t nr_pages = size / g_pal_state.alloc_align;
    ret = ocall_trim_epc_pages(addr, nr_pages);
    if (ret < 0) {
        log_debug("EPC trim page on [%p, %p) failed (%d)\n", addr, end, ret);
        return ret;
    }

    for (void* page_addr = addr; page_addr < end;
        page_addr = (void*)((char*)page_addr + g_pal_state.alloc_align)) {
        ret = sgx_accept(&secinfo, page_addr);
        if (ret) {
            log_debug("EDMM accept page failed while trimming: %p %d\n", page_addr, ret);
            return -EFAULT;
        }
    }

    ret = ocall_notify_accept(addr, nr_pages);
    if (ret < 0) {
        log_debug("EPC notify_accept on [%p, %p), %ld pages failed (%d)\n", addr, end, nr_pages, ret);
        return ret;
    }

    return 0;
}

/* This function allocates EPC pages within ELRANGE of an enclave. If EPC pages contain
 * executable code, page permissions are extended once the page is in a valid state. The
 * allocation sequence is described below:
 * 1. Enclave invokes EACCEPT on a new page request which triggers a page fault (#PF) as the page
 * is not available yet.
 * 2. Driver catches this #PF and issues EAUG for the page (at this point the page becomes VALID and
 * may be used by the enclave). The control returns back to enclave.
 * 3. Enclave continues the same EACCEPT and the instruction succeeds this time. */
int get_edmm_page_range(void* start, size_t size, bool executable) {
    void* lo = start;
    void* addr;
    int ret = 0;

#if PRINT_ENCLAVE_MEM_STAT
    __atomic_add_fetch(&g_stats_edmm_alloc_cnt, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_stats_edmm_alloc_size, size, __ATOMIC_SEQ_CST);
    if (size > __atomic_load_n(&g_stats_edmm_alloc_max_size, __ATOMIC_SEQ_CST))
        __atomic_store_n(&g_stats_edmm_alloc_max_size, size, __ATOMIC_SEQ_CST);

#endif

    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE)) {
        log_debug("%s: edmm alloc start_addr = %p, size = %lx\n", __func__, start, size);
    }

    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_LAZY)
            && (is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_BITMAP)
                || is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_WS_USE))) {

        size += g_page_size * EDMM_BATCH_SIZE - g_page_size;
#if 0
        int i;
        for (i = 1; ; i++) {
            unsigned long tmp_addr = (unsigned long)start + g_page_size * i;
            if (!edmm_bitmap_is_set(g_pal_sec.bitmap_i, tmp_addr)
                    || edmm_bitmap_is_set(g_pal_sec.bitmap_g, tmp_addr))
                break;
            if (edmm_bitmap_is_set(g_pal_sec.bitmap_i, (unsigned long)start + g_page_size * i))
                size += g_page_size;
        }
#endif
    }

    addr = lo + size;

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

#if 0
    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;
    _DkInternalLock(&g_edmm_vma_lock);

    LISTP_FOR_EACH_ENTRY(vma, &g_edmm_vma_list, list) {
        if (vma->bottom < (void *)lo) {
            break;
        }
        vma_above = vma;
    }
    edmm_create_vma_and_merge((void *)lo, size, vma_above);

    _DkInternalUnlock(&g_edmm_vma_lock);
#endif

    while (lo < addr) {
        addr = (void*)((char*)addr - g_pal_state.alloc_align);

        if (is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_BITMAP)
                || is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_WS_USE)) {
            if (!edmm_bitmap_is_set(g_pal_sec.bitmap_i, (unsigned long)addr))
                continue;

        }
        if (edmm_bitmap_is_set(g_pal_sec.bitmap_g, (unsigned long)addr))
            continue;
#if PRINT_ENCLAVE_MEM_STAT
        __atomic_add_fetch(&g_stats_edmm_runtime_size, g_page_size, __ATOMIC_SEQ_CST);
        if (__atomic_load_n(&g_stats_edmm_runtime_size, __ATOMIC_SEQ_CST) > __atomic_load_n(&g_stats_edmm_runtime_size_max, __ATOMIC_SEQ_CST))
            __atomic_store_n(&g_stats_edmm_runtime_size_max, __atomic_load_n(&g_stats_edmm_runtime_size, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
#endif
        ret = sgx_accept(&secinfo, addr);
        if (ret) {
            // TODO: need to judge whether the page has already been EACCEPTed
            if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE)) {
                log_debug("EDMM accept page failed: %p %d\n", addr, ret);
            }
            continue;
        }
        // assume bitmap used in all cases
        edmm_bitmap_set(g_pal_sec.bitmap_g, (unsigned long)addr);
        if (is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_WS_TRAIN))
            edmm_bitmap_set(g_pal_sec.bitmap_w, (unsigned long)addr);

        /* All new pages will have RW permissions initially, so after EAUG/EACCEPT, extend
         * permission of a VALID enclave page (if needed). */
        if (executable) {
            alignas(64) sgx_arch_sec_info_t secinfo_extend = secinfo;

            secinfo_extend.flags |= SGX_SECINFO_FLAGS_X;
            sgx_modpe(&secinfo_extend, addr);
        }
    }

    return ret;
}

static void* __create_vma_and_merge(void* addr, size_t size, bool is_pal_internal,
                                    struct heap_vma* vma_above) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));
    assert(addr && size);

    if (addr < g_heap_bottom)
        return NULL;

    /* find enclosing VMAs and check that pal-internal VMAs do not overlap with normal VMAs */
    struct heap_vma* vma_below;
    if (vma_above) {
        vma_below = LISTP_NEXT_ENTRY(vma_above, &g_heap_vma_list, list);
    } else {
        /* no VMA above `addr`; VMA right below `addr` must be the first (highest-address) in list */
        vma_below = LISTP_FIRST_ENTRY(&g_heap_vma_list, struct heap_vma, list);
    }

    /* check whether [addr, addr + size) overlaps with above VMAs of different type */
    struct heap_vma* check_vma_above = vma_above;
    while (check_vma_above && addr + size > check_vma_above->bottom) {
        if (check_vma_above->is_pal_internal != is_pal_internal) {
            return NULL;
        }
        check_vma_above = LISTP_PREV_ENTRY(check_vma_above, &g_heap_vma_list, list);
    }

    /* check whether [addr, addr + size) overlaps with below VMAs of different type */
    struct heap_vma* check_vma_below = vma_below;
    while (check_vma_below && addr < check_vma_below->top) {
        if (check_vma_below->is_pal_internal != is_pal_internal) {
            return NULL;
        }
        check_vma_below = LISTP_NEXT_ENTRY(check_vma_below, &g_heap_vma_list, list);
    }

    /* create VMA with [addr, addr+size); in case of existing overlapping VMAs, the created VMA is
     * merged with them and the old VMAs are discarded, similar to mmap(MAX_FIXED) */
    struct heap_vma* vma = __alloc_vma();
    if (!vma)
        return NULL;
    vma->bottom          = addr;
    vma->top             = addr + size;
    vma->is_pal_internal = is_pal_internal;

    /* how much memory was freed because [addr, addr + size) overlapped with VMAs */
    size_t freed = 0;

    /* Try to merge VMAs as an optimization:
     *   (1) start from `vma_above` and iterate through VMAs with higher-addresses for merges
     *   (2) start from `vma_below` and iterate through VMAs with lower-addresses for merges.
     * Note that we never merge normal VMAs with pal-internal VMAs. */
    while (vma_above && vma_above->bottom <= vma->top &&
           vma_above->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        freed += vma_above->top - vma_above->bottom;
        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_heap_vma_list, list);

        __free_vma(vma_above);
        vma_above = vma_above_above;
    }

    while (vma_below && vma_below->top >= vma->bottom &&
           vma_below->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
        freed += vma_below->top - vma_below->bottom;
        struct heap_vma* vma_below_below = LISTP_NEXT_ENTRY(vma_below, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_below->bottom, vma->bottom);
        vma->top    = MAX(vma_below->top, vma->top);
        LISTP_DEL(vma_below, &g_heap_vma_list, list);

        __free_vma(vma_below);
        vma_below = vma_below_below;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, vma_above, &g_heap_vma_list, list);

    if (vma->bottom >= vma->top) {
        log_error("Bad memory bookkeeping: %p - %p\n", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    assert(vma->top - vma->bottom >= (ptrdiff_t)freed);
    size_t allocated = vma->top - vma->bottom - freed;

    __atomic_add_fetch(&g_allocated_pages.counter, allocated / g_page_size, __ATOMIC_SEQ_CST);

    if (is_pal_internal) {
        assert(allocated <= g_pal_internal_mem_size - g_pal_internal_mem_used);
        g_pal_internal_mem_used += allocated;
    }

    return addr;
}

void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal) {
    void* ret = NULL;

    //log_debug("%s: edmm alloc start_addr = %p, size = %lx\n", __func__, addr, size);
    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));

    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;

    _DkInternalLock(&g_heap_vma_lock);

    if (is_pal_internal && size > g_pal_internal_mem_size - g_pal_internal_mem_used) {
        /* requested PAL-internal allocation would exceed the limit, fail */
        goto out;
    }

    if (addr) {
        /* caller specified concrete address; find VMA right-above this address */
        if (addr < g_heap_bottom || addr + size > g_heap_top)
            goto out;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->bottom < addr) {
                /* current VMA is not above `addr`, thus vma_above is VMA right-above `addr` */
                break;
            }
            vma_above = vma;
        }
        ret = __create_vma_and_merge(addr, size, is_pal_internal, vma_above);
    } else {
        /* caller did not specify address; find first (highest-address) empty slot that fits */
        void* vma_above_bottom = g_heap_top;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->top < vma_above_bottom - size) {
                ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal,
                                             vma_above);
                goto out;
            }
            vma_above = vma;
            vma_above_bottom = vma_above->bottom;
        }

        /* corner case: there may be enough space between heap bottom and the lowest-address VMA */
        if (g_heap_bottom < vma_above_bottom - size)
            ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal, vma_above);
    }

#if PRINT_ENCLAVE_MEM_STAT
    if (ret == NULL)
        goto out;

    __atomic_add_fetch(&g_stats_alloc_cnt, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_stats_alloc_size, size, __ATOMIC_SEQ_CST);

    if (size > __atomic_load_n(&g_stats_alloc_max_size, __ATOMIC_SEQ_CST))
        __atomic_store_n(&g_stats_alloc_max_size, size, __ATOMIC_SEQ_CST);

    __atomic_add_fetch(&g_stats_runtime_size, size, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&g_stats_runtime_size, __ATOMIC_SEQ_CST) > __atomic_load_n(&g_stats_runtime_size_max, __ATOMIC_SEQ_CST))
        __atomic_store_n(&g_stats_runtime_size_max, __atomic_load_n(&g_stats_runtime_size, __ATOMIC_SEQ_CST), __ATOMIC_SEQ_CST);
#endif

out:
    _DkInternalUnlock(&g_heap_vma_lock);

    if (is_sgx_edmm_batch(g_pal_sec.edmm_enable_heap, SGX_EDMM_BATCH_BITMAP) && ret != NULL) {
        unsigned long tmp_addr = (unsigned long)ret;
        unsigned long incr;
        for (incr = 0; incr < size; incr += g_page_size)
            edmm_bitmap_set(g_pal_sec.bitmap_o, tmp_addr+incr);
    }

    /* In order to prevent already accepted pages from being accepted again, we track EPC pages that
     * aren't accepted yet (unallocated heap) and call EACCEPT only on those EPC pages. */
    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NAIVE) && ret != NULL) {
        get_edmm_page_range(ret, size, 1);
    }
    return ret;
}

int free_enclave_pages(void* addr, size_t size) {
    int ret = 0;

    //log_debug("%s: edmm free start_addr = %p, size = %lx\n", __func__, addr, size);
    if (!size)
        return -PAL_ERROR_NOMEM;

#if PRINT_ENCLAVE_MEM_STAT
    __atomic_add_fetch(&g_stats_free_cnt, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_stats_free_size, size, __ATOMIC_SEQ_CST);
#endif

    size = ALIGN_UP(size, g_page_size);

    if (!access_ok(addr, size) || !IS_ALIGNED_PTR(addr, g_page_size) || addr < g_heap_bottom ||
            addr + size > g_heap_top) {
        return -PAL_ERROR_INVAL;
    }

    struct heap_vma* vma;
    struct heap_vma* p;

#if PRINT_ENCLAVE_MEM_STAT
    size_t __freed = 0;
#endif

    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NONE)
            || is_sgx_edmm_mempool(g_pal_sec.edmm_enable_heap, SGX_EDMM_MEMPOOL_NOFREE)) {
        goto skip_edmm_free;
    }

#if 0
    _DkInternalLock(&g_edmm_vma_lock);
#if 0
    log_debug("%s:%d freeing [%p, %p)\n", __func__, __LINE__,
            addr, addr + size);
#endif
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_edmm_vma_list, list) {
        if (vma->bottom >= addr + size)
            continue;
        if (vma->top <= addr)
            break;

#if 0
        log_debug("\tfound vma [%p, %p)\n",
                vma->bottom, vma->top);
#endif
        if (vma->bottom < addr) {
            struct heap_vma *new = __alloc_edmm_vma();
            if (!new) {
                log_error("*** Cannot create split VMA during freeing of address %p ***\n",
                        addr);
                break;
            }
            new->top = addr;
            new->bottom = vma->bottom;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        void *free_addr = MAX(vma->bottom, addr);
        size_t free_size = MIN(vma->top, addr + size) - MAX(vma->bottom, addr);
#if PRINT_ENCLAVE_MEM_STAT
        __freed += free_size;
#endif
#if 0
        log_debug("\tFreeing EDMM [%p, %p)\n",
                free_addr, free_addr + free_size);
        if (free_addr != addr || free_size != size) {
            log_debug("%s:%d freeing [%p, %p), vma [%p, %p), free [%p, %p)\n", __func__, __LINE__,
                    addr, addr + size,
                    vma->bottom, vma->top, free_addr, free_addr + free_size);
        }
#endif
        free_edmm_page_range(free_addr, free_size);

        vma->bottom = addr + size;
        if (vma->top <= addr + size) {
            LISTP_DEL(vma, &g_edmm_vma_list, list);
            __free_edmm_vma(vma);
        }
    }
#if PRINT_ENCLAVE_MEM_STAT
    __atomic_add_fetch(&g_stats_edmm_freed_size, __freed, __ATOMIC_SEQ_CST);
#endif
    _DkInternalUnlock(&g_edmm_vma_lock);
#endif

    void *tmp_addr = addr;
    void *end_addr = addr + size;
    //log_error("%s:%d addr %p size %lu end_addr %p\n", __func__, __LINE__, addr, size, addr+size);
    while (1) {
        while (tmp_addr < end_addr && !edmm_bitmap_is_set(g_pal_sec.bitmap_g, (unsigned long)tmp_addr))
            tmp_addr += g_page_size;

        if (tmp_addr >= end_addr)
            break;

        void *free_addr = tmp_addr;

        edmm_bitmap_clear(g_pal_sec.bitmap_g, (unsigned long)tmp_addr);
        for (tmp_addr = free_addr + g_page_size;
                tmp_addr < end_addr && edmm_bitmap_is_set(g_pal_sec.bitmap_g, (unsigned long)tmp_addr);
                tmp_addr += g_page_size) {
            edmm_bitmap_clear(g_pal_sec.bitmap_g, (unsigned long)tmp_addr);
        }

        size_t free_size = tmp_addr - free_addr;
#if PRINT_ENCLAVE_MEM_STAT
        __atomic_add_fetch(&g_stats_edmm_freed_size, free_size, __ATOMIC_SEQ_CST);
#endif

        //log_error("%s:%d free_addr %p end_addr %p free_size %lu\n", __func__, __LINE__, free_addr, tmp_addr, free_size);
        free_edmm_page_range(free_addr, free_size);
    }

skip_edmm_free:
    _DkInternalLock(&g_heap_vma_lock);

    /* VMA list contains both normal and pal-internal VMAs; it is impossible to free an area
     * that overlaps with VMAs of two types at the same time, so we fail in such cases */
    bool is_pal_internal_set = false;
    bool is_pal_internal = false;

    /* how much memory was actually freed, since [addr, addr + size) can overlap with VMAs */
    size_t freed = 0;

    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        if (vma->bottom >= addr + size)
            continue;
        if (vma->top <= addr)
            break;

        /* found VMA overlapping with area to free; check it is either normal or pal-internal */
        if (!is_pal_internal_set) {
            is_pal_internal = vma->is_pal_internal;
            is_pal_internal_set = true;
        }

        if (is_pal_internal != vma->is_pal_internal) {
            log_error("Area to free (address %p, size %lu) overlaps with both normal and "
                      "pal-internal VMAs\n",
                      addr, size);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        freed += MIN(vma->top, addr + size) - MAX(vma->bottom, addr);

        if (vma->bottom < addr) {
            /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
            struct heap_vma* new = __alloc_vma();
            if (!new) {
                log_error("Cannot create split VMA during freeing of address %p\n", addr);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }
            new->top             = addr;
            new->bottom          = vma->bottom;
            new->is_pal_internal = vma->is_pal_internal;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        /* compress overlapping VMA to [addr + size, vma->top) */
        vma->bottom = addr + size;
        if (vma->top <= addr + size) {
            /* memory area to free completely covers/extends above the rest of the VMA */
            LISTP_DEL(vma, &g_heap_vma_list, list);
            __free_vma(vma);
        }
    }

#if PRINT_ENCLAVE_MEM_STAT
    __atomic_add_fetch(&g_stats_freed_size, freed, __ATOMIC_SEQ_CST);
    __atomic_sub_fetch(&g_stats_runtime_size, freed, __ATOMIC_SEQ_CST);
#endif

    __atomic_sub_fetch(&g_allocated_pages.counter, freed / g_page_size, __ATOMIC_SEQ_CST);

    if (is_pal_internal_set && is_pal_internal) {
        assert(g_pal_internal_mem_used >= freed);
        g_pal_internal_mem_used -= freed;
    }

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return ret;
}

int zero_enclave_pages(void *start, size_t size)
{
    void *tmp_addr = start;
    void *end_addr = start + size;
    PAL_PTR bitmap = g_pal_sec.bitmap_g;
    /* For non-EDMM enclave, just zero the whole region */
    if (is_sgx_edmm_mode(g_pal_sec.edmm_enable_heap, SGX_EDMM_MODE_NONE)) {
        memset(start, 0, size);
        return 0;
    }

    /* For EDMM enclave, only zero those regions that has EPC allocated,
     * unallocated region will be zeroed by EAUG upon allocation
     */
    while (1) {
        for ( ;
                tmp_addr < end_addr && !edmm_bitmap_is_set(bitmap, (unsigned long)tmp_addr);
                tmp_addr += g_page_size)
            /* Do nothing */;

        if (tmp_addr >= end_addr)
            break;
        void *zero_addr = tmp_addr;

        for (tmp_addr = zero_addr + g_page_size;
                tmp_addr < end_addr && edmm_bitmap_is_set(bitmap, (unsigned long)tmp_addr);
                tmp_addr += g_page_size)
            /* Do nothing */;

        memset(zero_addr, 0, tmp_addr - zero_addr);
    }

    return 0;
}

/* returns current highest available address on the enclave heap */
void* get_enclave_heap_top(void) {
    _DkInternalLock(&g_heap_vma_lock);

    void* addr = g_heap_top;
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
        if (vma->top < addr) {
            goto out;
        }
        addr = vma->bottom;
    }

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return addr;
}

void enclave_page_print_stats(void)
{
#if PRINT_ENCLAVE_MEM_STAT
    _DkInternalLock(&g_enclave_stats_lock);

    log_error("----- Enclave Memory stats -----\n"
            "  enclave_runtime (KiB)        | edmm_runtime:         %8lu | %8lu\n"
            "  enclave_runtime_max (KiB)    | edmm_runtime_max:     %8lu | %8lu\n"
            "  enclave_alloc_cnt            | edmm_alloc_cnt:       %8lu | %8lu\n"
            "  enclave_alloc_size (KiB)     | edmm_alloc_size:      %8lu | %8lu\n"
            "  enclave_alloc_max_size (KiB) | edmm_alloc_max_size:  %8lu | %8lu\n"
            "  enclave_free_cnt             | edmm_free_cnt:        %8lu | %8lu\n"
            "  enclave_free_size (KiB)      | edmm_free_size:       %8lu | %8lu\n"
            "  enclave_freed_size (KiB)     | edmm_freed_size:      %8lu | %8lu\n",
            (g_stats_runtime_size)/1024, (g_stats_edmm_runtime_size)/1024,
            (g_stats_runtime_size_max)/1024, (g_stats_edmm_runtime_size_max)/1024,
            (g_stats_alloc_cnt), (g_stats_edmm_alloc_cnt),
            (g_stats_alloc_size)/1024, (g_stats_edmm_alloc_size)/1024,
            (g_stats_alloc_max_size)/1024, (g_stats_edmm_alloc_max_size)/1024,
            (g_stats_free_cnt), (g_stats_edmm_free_cnt),
            (g_stats_free_size)/1024, (g_stats_edmm_free_size)/1024,
            (g_stats_freed_size)/1024, (g_stats_edmm_freed_size)/1024
            );
    _DkInternalUnlock(&g_enclave_stats_lock);
#endif
}

#include <stdbool.h>
#include <stddef.h>

int init_enclave_pages(void);
void* get_enclave_heap_top(void);
void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal);
int free_enclave_pages(void* addr, size_t size);
int get_edmm_page_range(void *addr, size_t size, bool executable);
int free_edmm_page_range(void *start, size_t size);
int zero_enclave_pages(void *start, size_t size);
void enclave_page_print_stats(void);

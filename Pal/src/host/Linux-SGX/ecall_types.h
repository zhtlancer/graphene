#include <stddef.h>

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_THREAD_RESET,
    ECALL_PLACEHOLDER,
    ECALL_ALLOCATE_PAGE,
    ECALL_NR,
};

struct pal_sec;
struct rpc_queue;

typedef struct {
    char*             ms_args;
    size_t            ms_args_size;
    char*             ms_env;
    size_t            ms_env_size;
    struct pal_sec*   ms_sec_info;
    struct rpc_queue* rpc_queue; /* pointer to RPC queue in untrusted mem */
} ms_ecall_enclave_start_t;

#include "pal_linux.h"
#include "pal_security.h"

/* batch size for batch EPC allocation */
#define EAUG_CHUNK_SIZE     (1UL<<20)
#define EAUG_CHUNK_PAGENUM  (EAUG_CHUNK_SIZE/PRESET_PAGESIZE)

int ecall_enclave_start(char* args, size_t args_size, char* env, size_t env_size);

int ecall_thread_start(void);

int ecall_thread_reset(void);

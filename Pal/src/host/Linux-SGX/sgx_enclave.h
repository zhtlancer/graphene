/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_linux.h"
#include "pal_security.h"

int ecall_enclave_start (const char ** arguments, const char ** environments);

int ecall_thread_start (void);

int ecall_stack_expand (void * fault_addr);

int ecall_thread_setup (void * thread_info);

int ecall_thread_create(void * thread_info);

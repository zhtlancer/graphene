/* Copyright (C) 2019-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PROTECTED_FILE_FORMAT_H_
#define PROTECTED_FILE_FORMAT_H_

/* for SSIZE_MAX */
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "protected_files.h"

#define SGX_FILE_ID            0x5347585F46494C45 /* SGX_FILE */
#define SGX_FILE_MAJOR_VERSION 0x01
#define SGX_FILE_MINOR_VERSION 0x00

#pragma pack(push, 1)

typedef struct _meta_data_plain {
    uint64_t file_id;
    uint8_t  major_version;
    uint8_t  minor_version;

    pf_keyid_t meta_data_key_id;

    pf_mac_t meta_data_gmac;
    uint8_t  update_flag;
} meta_data_plain_t;

// these are all defined as relative to node size, so we can decrease node size in tests
// and have deeper tree
#define FILENAME_MAX_LEN      260
#define PATHNAME_MAX_LEN      (512)
#define FULLNAME_MAX_LEN      (PATHNAME_MAX_LEN + FILENAME_MAX_LEN)
#define RECOVERY_FILE_MAX_LEN (FULLNAME_MAX_LEN + 10)

#define MD_USER_DATA_SIZE (PF_NODE_SIZE*3/4)  // 3072
static_assert(MD_USER_DATA_SIZE == 3072, "bad struct size");

typedef struct _meta_data_encrypted {
    char     clean_filename[FULLNAME_MAX_LEN];
    int64_t  size;
    pf_key_t mht_key;
    pf_mac_t mht_gmac;
    uint8_t  data[MD_USER_DATA_SIZE];
} meta_data_encrypted_t;

typedef uint8_t meta_data_encrypted_blob_t[sizeof(meta_data_encrypted_t)];

#define META_DATA_NODE_SIZE PF_NODE_SIZE
static_assert(PF_NODE_SIZE <= SSIZE_MAX, "PF_NODE_SIZE <= SSIZE_MAX");

typedef uint8_t meta_data_padding_t[META_DATA_NODE_SIZE
    - (sizeof(meta_data_plain_t) + sizeof(meta_data_encrypted_blob_t))];

typedef struct _meta_data_node {
    meta_data_plain_t          plain_part;
    meta_data_encrypted_blob_t encrypted_part;
    meta_data_padding_t        padding;
} meta_data_node_t;

static_assert(sizeof(meta_data_node_t) == PF_NODE_SIZE, "sizeof(meta_data_node_t)");

typedef struct _data_node_crypto {
    pf_key_t key;
    pf_mac_t gmac;
} gcm_crypto_data_t;

// for PF_NODE_SIZE == 4096, we have 96 attached data nodes and 32 mht child nodes
// for PF_NODE_SIZE == 2048, we have 48 attached data nodes and 16 mht child nodes
// for PF_NODE_SIZE == 1024, we have 24 attached data nodes and 8 mht child nodes
// 3/4 of the node size is dedicated to data nodes
#define ATTACHED_DATA_NODES_COUNT ((PF_NODE_SIZE/sizeof(gcm_crypto_data_t))*3/4)
static_assert(ATTACHED_DATA_NODES_COUNT == 96, "ATTACHED_DATA_NODES_COUNT");
// 1/4 of the node size is dedicated to child mht nodes
#define CHILD_MHT_NODES_COUNT ((PF_NODE_SIZE/sizeof(gcm_crypto_data_t))*1/4)
static_assert(CHILD_MHT_NODES_COUNT == 32, "CHILD_MHT_NODES_COUNT");

typedef struct _mht_node {
    gcm_crypto_data_t data_nodes_crypto[ATTACHED_DATA_NODES_COUNT];
    gcm_crypto_data_t mht_nodes_crypto[CHILD_MHT_NODES_COUNT];
} mht_node_t;

static_assert(sizeof(mht_node_t) == PF_NODE_SIZE, "sizeof(mht_node_t)");

typedef struct _data_node {
    uint8_t data[PF_NODE_SIZE];
} data_node_t;

static_assert(sizeof(data_node_t) == PF_NODE_SIZE, "sizeof(data_node_t)");

// make sure these are the same size
static_assert(sizeof(mht_node_t) == sizeof(data_node_t),
              "sizeof(mht_node_t) == sizeof(data_node_t)");

typedef struct _encrypted_node {
    uint8_t cipher[PF_NODE_SIZE];
} encrypted_node_t;

static_assert(sizeof(encrypted_node_t) == PF_NODE_SIZE, "sizeof(encrypted_node_t)");

typedef struct _recovery_node {
    uint64_t physical_node_number;
    uint8_t  node_data[PF_NODE_SIZE];
} recovery_node_t;

#define MASTER_KEY_NAME       "SGX-PROTECTED-FS-MASTER-KEY"
#define RANDOM_KEY_NAME       "SGX-PROTECTED-FS-RANDOM-KEY"
#define METADATA_KEY_NAME     "SGX-PROTECTED-FS-METADATA-KEY"
#define MAX_LABEL_LEN         64
#define MAX_MASTER_KEY_USAGES 65536

typedef struct {
    uint32_t index;
    char label[MAX_LABEL_LEN];
    uint64_t node_number; // context 1
    union { // context 2
        pf_mac_t nonce16;
        pf_keyid_t nonce32; // sgx_key_id_t
    };
    uint32_t output_len; // in bits
} kdf_input_t;

#pragma pack(pop)

#endif /* PROTECTED_FILE_FORMAT_H_ */

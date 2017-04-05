/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_FW_SRC_MGOS_ATCA_INTERNAL_H_
#define CS_FW_SRC_MGOS_ATCA_INTERNAL_H_

#include "fw/src/mgos_features.h"

#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if MGOS_ENABLE_ATCA
typedef enum _KeyType {
	KEY_TYPE_ECC,
	KEY_TYPE_NON_ECC,
} KeyType;

typedef struct _key_config_t {
	uint8_t private;           // 0
	uint8_t pub_info;          // 1
	KeyType key_type;          // 2, 3, 4
	uint8_t lockable;          // 5
	uint8_t req_random;        // 6
	uint8_t req_auth;          // 7
	uint8_t auth_key;          // 8,9,10,11
	uint8_t intrusion_disable; // 12
	// uint8_t _reserved;      // 13
	uint8_t x509_id;           // 14,15
} key_config_t;

ATCA_STATUS get_key_config(uint8_t slot, key_config_t *key_config);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_FW_SRC_MGOS_ATCA_INTERNAL_H_ */

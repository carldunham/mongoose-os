/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#include "fw/src/mgos_atca_internal.h"

#if MGOS_ENABLE_ATCA

#include "common/cs_dbg.h"

#include "cryptoauthlib.h"

ATCA_STATUS get_key_config(uint8_t slot, key_config_t *key_config) {
	uint8_t data[ATCA_WORD_SIZE];

	ATCA_STATUS status =
		atcab_read_zone(ATCA_ZONE_CONFIG, 0 /* slot */, 3 /* block */,
						(slot >> 1) /* offset */, data, ATCA_WORD_SIZE);

    if (status != ATCA_SUCCESS) {
		return status;
	}
	uint8_t *d = data + ((slot & 0x01) ? 2 : 0);

	key_config->private =           (*d & 0x01);
	key_config->pub_info =          (*d & 0x02) >> 1;
	key_config->key_type =          ((*d & 0x1c) == 0x10) ?
										KEY_TYPE_ECC : KEY_TYPE_NON_ECC;
	key_config->lockable =          (*d & 0x20) >> 5;
	key_config->req_random =        (*d & 0x40) >> 6;
	key_config->req_auth =          (*d & 0x80) >> 7;

	d++;
	key_config->auth_key =          (*d & 0x0f);
	key_config->intrusion_disable = (*d & 0x10) >> 4;
	key_config->x509_id =           (*d >> 6);

	LOG(LL_DEBUG, ("KeyConfig for Slot %d:", slot));
	LOG(LL_DEBUG, ("    Private: %d", key_config->private));
	LOG(LL_DEBUG, ("    PubInfo: %d", key_config->pub_info));
	LOG(LL_DEBUG, ("    KeyType: %s", key_config->key_type == KEY_TYPE_ECC ?
											"ECC" : "NonECC"));
	LOG(LL_DEBUG, ("    Lockable: %d", key_config->lockable));
	LOG(LL_DEBUG, ("    ReqRandom: %d", key_config->req_random));
	LOG(LL_DEBUG, ("    ReqAuth: %d", key_config->req_auth));
	LOG(LL_DEBUG, ("    AuthKey: %d", key_config->auth_key));
	LOG(LL_DEBUG, ("    IntrusionDisable: %d", key_config->intrusion_disable));
	LOG(LL_DEBUG, ("    X509ID: %d", key_config->x509_id));

	return ATCA_SUCCESS;
}
#endif /* MGOS_ENABLE_ATCA */

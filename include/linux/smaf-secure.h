/*
 * smaf-secure.h
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 */

#ifndef _SMAF_SECURE_H_
#define _SMAF_SECURE_H_

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>

/**
 * struct smaf_secure
 * @create_ctx:		create a context for one dmabuf.
 *			If success return an opaque pointer on secure context
 *			either return NULL.
 * @destroy_ctx:	destroy context.
 * @grant_access:	check and provide access to memory area for a specific
 *			device. Return true if the request is valid.
 * @revoke_access:	remove device access rights.
 */
struct smaf_secure {
	void *(*create_ctx)(void);
	int (*destroy_ctx)(void *ctx);
	bool (*grant_access)(void *ctx,
			     struct device *dev,
			     size_t addr, size_t size,
			     enum dma_data_direction direction);
	void (*revoke_access)(void *ctx,
			      struct device *dev,
			      size_t addr, size_t size,
			      enum dma_data_direction direction);
};

/**
 * smaf_register_secure - register secure module helper
 * Secure module helper should be platform specific so only one can be
 * registered.
 *
 * @sec: secure module to be registered
 */
int smaf_register_secure(struct smaf_secure *sec);

/**
 * smaf_unregister_secure - unregister secure module helper
 */
void smaf_unregister_secure(struct smaf_secure *sec);

/**
 * smaf_is_secure - test is a dma_buf handle has been secured by SMAF
 * @dmabuf: dma_buf handle to be tested
 */
bool smaf_is_secure(struct dma_buf *dmabuf);

/**
 * smaf_set_secure - change dma_buf handle secure status
 * @dmabuf: dma_buf handle to be change
 * @secure: if true secure dma_buf handle
 */
int smaf_set_secure(struct dma_buf *dmabuf, bool secure);

#endif

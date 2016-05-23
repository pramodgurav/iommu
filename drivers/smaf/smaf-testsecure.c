/*
 * smaf-testsecure.c
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf-secure.h>

#define MAGIC 0xDEADBEEF

struct test_private {
	int magic;
};

#define to_priv(x) (struct test_private *)(x)

static void *smaf_testsecure_create(void)
{
	struct test_private *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->magic = MAGIC;

	return priv;
}

static int smaf_testsecure_destroy(void *ctx)
{
	struct test_private *priv = to_priv(ctx);

	WARN_ON(!priv || (priv->magic != MAGIC));
	kfree(priv);

	return 0;
}

static bool smaf_testsecure_grant_access(void *ctx,
					 struct device *dev,
					 size_t addr, size_t size,
					 enum dma_data_direction direction)
{
	struct test_private *priv = to_priv(ctx);

	WARN_ON(!priv || (priv->magic != MAGIC));
	pr_debug("grant requested by device %s\n",
		 dev->driver ? dev->driver->name : "cpu");

	return priv->magic == MAGIC;
}

static void smaf_testsecure_revoke_access(void *ctx,
					  struct device *dev,
					  size_t addr, size_t size,
					  enum dma_data_direction direction)
{
	struct test_private *priv = to_priv(ctx);

	WARN_ON(!priv || (priv->magic != MAGIC));
	pr_debug("revoke requested by device %s\n",
		 dev->driver ? dev->driver->name : "cpu");
}

static struct smaf_secure test = {
	.create_ctx = smaf_testsecure_create,
	.destroy_ctx = smaf_testsecure_destroy,
	.grant_access = smaf_testsecure_grant_access,
	.revoke_access = smaf_testsecure_revoke_access,
};

static int __init smaf_testsecure_init(void)
{
	return smaf_register_secure(&test);
}
module_init(smaf_testsecure_init);

static void __exit smaf_testsecure_deinit(void)
{
	smaf_unregister_secure(&test);
}
module_exit(smaf_testsecure_deinit);

MODULE_DESCRIPTION("SMAF secure module for test purpose");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Benjamin Gaignard <benjamin.gaignard@linaro.org>");

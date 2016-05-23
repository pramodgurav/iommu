/*
 * smaf-cma.c
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 */

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf-allocator.h>

struct smaf_cma_buffer_info {
	struct device *dev;
	size_t size;
	void *vaddr;
	dma_addr_t paddr;
	struct dma_attrs attrs;
};

/**
 * find_matching_device - iterate over the attached devices to find one
 * with coherent_dma_mask correctly set to DMA_BIT_MASK(32).
 * Matching device (if any) will be used to aim CMA area.
 */
static struct device *find_matching_device(struct dma_buf *dmabuf)
{
	struct dma_buf_attachment *attach_obj;

	list_for_each_entry(attach_obj, &dmabuf->attachments, node) {
		if (attach_obj->dev->coherent_dma_mask == DMA_BIT_MASK(32))
			return attach_obj->dev;
	}

	return NULL;
}

/**
 * smaf_cma_match - return true if at least one device has been found
 */
static bool smaf_cma_match(struct dma_buf *dmabuf)
{
	return !!find_matching_device(dmabuf);
}

static void smaf_cma_release(struct dma_buf *dmabuf)
{
	struct smaf_cma_buffer_info *info = dmabuf->priv;

	dma_free_attrs(info->dev, info->size, info->vaddr,
		       info->paddr, &info->attrs);

	kfree(info);
}

static struct sg_table *smaf_cma_map(struct dma_buf_attachment *attachment,
				     enum dma_data_direction direction)
{
	struct smaf_cma_buffer_info *info = attachment->dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	ret = dma_get_sgtable(info->dev, sgt, info->vaddr,
			      info->paddr, info->size);
	if (ret < 0)
		goto out;

	sg_dma_address(sgt->sgl) = info->paddr;
	return sgt;

out:
	kfree(sgt);
	return NULL;
}

static void smaf_cma_unmap(struct dma_buf_attachment *attachment,
			   struct sg_table *sgt,
			   enum dma_data_direction direction)
{
	/* do nothing */
}

static int smaf_cma_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct smaf_cma_buffer_info *info = dmabuf->priv;

	if (info->size < vma->vm_end - vma->vm_start)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	return dma_mmap_attrs(info->dev, vma, info->vaddr, info->paddr,
			      info->size, &info->attrs);
}

static void *smaf_cma_vmap(struct dma_buf *dmabuf)
{
	struct smaf_cma_buffer_info *info = dmabuf->priv;

	return info->vaddr;
}

static void *smaf_kmap_atomic(struct dma_buf *dmabuf, unsigned long offset)
{
	struct smaf_cma_buffer_info *info = dmabuf->priv;

	return (void *)info->vaddr + offset;
}

static const struct dma_buf_ops smaf_cma_ops = {
	.map_dma_buf = smaf_cma_map,
	.unmap_dma_buf = smaf_cma_unmap,
	.mmap = smaf_cma_mmap,
	.release = smaf_cma_release,
	.kmap_atomic = smaf_kmap_atomic,
	.kmap = smaf_kmap_atomic,
	.vmap = smaf_cma_vmap,
};

static struct dma_buf *smaf_cma_allocate(struct dma_buf *dmabuf, size_t length)
{
	struct dma_buf_attachment *attach_obj;
	struct smaf_cma_buffer_info *info;
	struct dma_buf *cma_dmabuf;

	DEFINE_DMA_BUF_EXPORT_INFO(export);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return NULL;

	dma_set_attr(DMA_ATTR_WRITE_COMBINE, &info->attrs);

	info->dev = find_matching_device(dmabuf);
	info->size = length;
	info->vaddr = dma_alloc_attrs(info->dev, info->size, &info->paddr,
				      GFP_KERNEL | __GFP_NOWARN, &info->attrs);
	if (!info->vaddr)
		goto alloc_error;

	export.ops = &smaf_cma_ops;
	export.size = info->size;
	export.priv = info;

	cma_dmabuf = dma_buf_export(&export);
	if (IS_ERR(cma_dmabuf))
		goto export_error;

	list_for_each_entry(attach_obj, &dmabuf->attachments, node) {
		dma_buf_attach(cma_dmabuf, attach_obj->dev);
	}

	return cma_dmabuf;

export_error:
	dma_free_attrs(info->dev, info->size, &info->paddr,
		       GFP_KERNEL | __GFP_NOWARN, &info->attrs);
alloc_error:
	kfree(info);
	return NULL;
}

static struct smaf_allocator smaf_cma = {
	.match = smaf_cma_match,
	.allocate = smaf_cma_allocate,
	.name = "smaf-cma",
	.ranking = 0,
};

static int __init smaf_cma_init(void)
{
	return smaf_register_allocator(&smaf_cma);
}
module_init(smaf_cma_init);

static void __exit smaf_cma_deinit(void)
{
	smaf_unregister_allocator(&smaf_cma);
}
module_exit(smaf_cma_deinit);

MODULE_DESCRIPTION("SMAF CMA module");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Benjamin Gaignard <benjamin.gaignard@linaro.org>");

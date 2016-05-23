/*
 * smaf-core.c
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 *
 * Secure Memory Allocator Framework (SMAF) allow to register memory
 * allocators and a secure module under a common API.
 * Multiple allocators can be registered to fit with hardwrae devices
 * requirement. Each allocator must provide a match() function to check
 * it capaticity to handle the devices attached (like defined by dmabuf).
 * Only one secure module can be registered since it dedicated to one
 * hardware platform.
 */

#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/list_sort.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf.h>
#include <linux/smaf-allocator.h>
#include <linux/smaf-secure.h>
#include <linux/uaccess.h>

struct smaf_handle {
	struct dma_buf *dmabuf;
	struct smaf_allocator *allocator;
	struct dma_buf *db_alloc;
	size_t length;
	unsigned int flags;
	int fd;
	atomic_t is_secure;
	void *secure_ctx;
};

/**
 * struct smaf_device - smaf device node private data
 * @misc_dev:	the misc device
 * @head:	list of allocator
 * @lock:	list and secure pointer mutex
 * @secure:	pointer to secure functions helpers
 */
struct smaf_device {
	struct miscdevice misc_dev;
	struct list_head head;
	/* list and secure pointer lock*/
	struct mutex lock;
	struct smaf_secure *secure;
};

static long smaf_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations smaf_fops = {
	.unlocked_ioctl = smaf_ioctl,
};

static struct smaf_device smaf_dev = {
	.misc_dev.minor = MISC_DYNAMIC_MINOR,
	.misc_dev.name  = "smaf",
	.misc_dev.fops  = &smaf_fops,
};

static bool have_secure_module(void)
{
	return !!smaf_dev.secure;
}

/**
 * smaf_grant_access - return true if the specified device can get access
 * to the memory area
 *
 * This function must be called with smaf_dev.lock set
 */
static bool smaf_grant_access(struct smaf_handle *handle, struct device *dev,
			      dma_addr_t addr, size_t size,
			      enum dma_data_direction dir)
{
	if (!atomic_read(&handle->is_secure))
		return true;

	if (!have_secure_module())
		return false;

	return smaf_dev.secure->grant_access(handle->secure_ctx,
					     dev, addr, size, dir);
}

/**
 * smaf_revoke_access
 * This function must be called with smaf_dev.lock set
 */
static void smaf_revoke_access(struct smaf_handle *handle, struct device *dev,
			       dma_addr_t addr, size_t size,
			       enum dma_data_direction dir)
{
	if (!atomic_read(&handle->is_secure))
		return;

	if (!have_secure_module())
		return;

	smaf_dev.secure->revoke_access(handle->secure_ctx,
				       dev, addr, size, dir);
}

static int smaf_secure_handle(struct smaf_handle *handle)
{
	void *ctx;

	if (atomic_read(&handle->is_secure))
		return 0;

	if (!have_secure_module())
		return -EINVAL;

	ctx = smaf_dev.secure->create_ctx();

	if (!ctx)
		return -EINVAL;

	handle->secure_ctx = ctx;

	atomic_set(&handle->is_secure, 1);
	return 0;
}

static int smaf_unsecure_handle(struct smaf_handle *handle)
{
	if (!atomic_read(&handle->is_secure))
		return 0;

	if (!have_secure_module())
		return -EINVAL;

	if (smaf_dev.secure->destroy_ctx(handle->secure_ctx))
		return -EINVAL;

	handle->secure_ctx = NULL;
	atomic_set(&handle->is_secure, 0);
	return 0;
}

int smaf_register_secure(struct smaf_secure *s)
{
	/* make sure that secure module have all required functions
	 * to avoid test them each time later
	 */
	if (!s || !s->create_ctx || !s->destroy_ctx ||
	    !s->grant_access || !s->revoke_access)
		return -EINVAL;

	mutex_lock(&smaf_dev.lock);
	smaf_dev.secure = s;
	mutex_unlock(&smaf_dev.lock);

	return 0;
}
EXPORT_SYMBOL(smaf_register_secure);

void smaf_unregister_secure(struct smaf_secure *s)
{
	mutex_lock(&smaf_dev.lock);
	if (smaf_dev.secure == s)
		smaf_dev.secure = NULL;
	mutex_unlock(&smaf_dev.lock);
}
EXPORT_SYMBOL(smaf_unregister_secure);

static struct smaf_allocator *smaf_find_allocator(struct dma_buf *dmabuf)
{
	struct smaf_allocator *alloc;

	list_for_each_entry(alloc, &smaf_dev.head, list_node) {
		if (alloc->match(dmabuf))
			return alloc;
	}

	return NULL;
}

static struct smaf_allocator *smaf_get_first_allocator(struct dma_buf *dmabuf)
{
	/* the first allocator of the list is the preferred allocator */
	return list_first_entry(&smaf_dev.head, struct smaf_allocator,
			list_node);
}

static int smaf_allocate(struct smaf_handle *handle, struct dma_buf *dmabuf)
{
	/* try to find an allocator */
	if (!handle->allocator) {
		struct smaf_allocator *alloc;

		mutex_lock(&smaf_dev.lock);
		if (list_empty(&dmabuf->attachments)) {
			/* no devices attached by default select the first
			 * allocator
			 */
			alloc = smaf_get_first_allocator(dmabuf);
		} else {
			alloc = smaf_find_allocator(dmabuf);
		}
		mutex_unlock(&smaf_dev.lock);

		/* still no allocator ? */
		if (!alloc)
			return -EINVAL;

		handle->allocator = alloc;
	}

	/* allocate memory */
	if (!handle->db_alloc) {
		struct dma_buf *db_alloc;

		db_alloc = handle->allocator->allocate(dmabuf, handle->length);
		if (!db_alloc)
			return -EINVAL;

		handle->db_alloc = db_alloc;
	}

	return 0;
}

static int smaf_allocator_compare(void *priv,
				  struct list_head *lh_a,
				  struct list_head *lh_b)
{
	struct smaf_allocator *a = list_entry(lh_a,
					      struct smaf_allocator, list_node);
	struct smaf_allocator *b = list_entry(lh_b,
					      struct smaf_allocator, list_node);
	int diff;

	diff = b->ranking - a->ranking;
	if (diff)
		return diff;

	return strcmp(a->name, b->name);
}

int smaf_register_allocator(struct smaf_allocator *alloc)
{
	if (!alloc || !alloc->match || !alloc->allocate || !alloc->name)
		return -EINVAL;

	mutex_lock(&smaf_dev.lock);
	INIT_LIST_HEAD(&alloc->list_node);
	list_add(&alloc->list_node, &smaf_dev.head);
	list_sort(NULL, &smaf_dev.head, smaf_allocator_compare);
	mutex_unlock(&smaf_dev.lock);

	return 0;
}
EXPORT_SYMBOL(smaf_register_allocator);

void smaf_unregister_allocator(struct smaf_allocator *alloc)
{
	mutex_lock(&smaf_dev.lock);
	list_del(&alloc->list_node);
	mutex_unlock(&smaf_dev.lock);
}
EXPORT_SYMBOL(smaf_unregister_allocator);

static struct dma_buf_attachment *smaf_find_attachment(struct dma_buf *db_alloc,
						       struct device *dev)
{
	struct dma_buf_attachment *attach_obj;

	list_for_each_entry(attach_obj, &db_alloc->attachments, node) {
		if (attach_obj->dev == dev)
			return attach_obj;
	}

	return NULL;
}

static struct sg_table *smaf_map_dma_buf(struct dma_buf_attachment *attachment,
					 enum dma_data_direction direction)
{
	struct dma_buf_attachment *db_attachment;
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct smaf_handle *handle = dmabuf->priv;
	struct sg_table *sgt;
	unsigned int count_done, count;
	struct scatterlist *sg;

	if (smaf_allocate(handle, dmabuf))
		return NULL;

	db_attachment = smaf_find_attachment(handle->db_alloc, attachment->dev);
	sgt = dma_buf_map_attachment(db_attachment, direction);

	if (!sgt)
		return NULL;

	if (!atomic_read(&handle->is_secure))
		return sgt;

	mutex_lock(&smaf_dev.lock);

	/* now secure the data */
	for_each_sg(sgt->sgl, sg, sgt->nents, count_done) {
		if (!smaf_grant_access(handle, db_attachment->dev,
				       sg_phys(sg), sg->length, direction))
			goto failed;
	}

	mutex_unlock(&smaf_dev.lock);
	return sgt;

failed:
	for_each_sg(sgt->sgl, sg, count_done, count) {
		smaf_revoke_access(handle, db_attachment->dev,
				   sg_phys(sg), sg->length, direction);
	}

	mutex_unlock(&smaf_dev.lock);

	sg_free_table(sgt);
	kfree(sgt);
	return NULL;
}

static void smaf_unmap_dma_buf(struct dma_buf_attachment *attachment,
			       struct sg_table *sgt,
			       enum dma_data_direction direction)
{
	struct dma_buf_attachment *db_attachment;
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct smaf_handle *handle = dmabuf->priv;
	struct scatterlist *sg;
	unsigned int count;

	if (!handle->db_alloc)
		return;

	db_attachment = smaf_find_attachment(handle->db_alloc, attachment->dev);
	if (!db_attachment)
		return;

	if (atomic_read(&handle->is_secure)) {
		mutex_lock(&smaf_dev.lock);
		for_each_sg(sgt->sgl, sg, sgt->nents, count) {
			smaf_revoke_access(handle, db_attachment->dev,
					   sg_phys(sg), sg->length, direction);
		}
		mutex_unlock(&smaf_dev.lock);
	}

	dma_buf_unmap_attachment(db_attachment, sgt, direction);
}

static void smaf_vm_close(struct vm_area_struct *vma)
{
	struct smaf_handle *handle = vma->vm_private_data;
	enum dma_data_direction dir;

	if (vma->vm_flags == VM_READ)
		dir = DMA_TO_DEVICE;

	if (vma->vm_flags == VM_WRITE)
		dir = DMA_FROM_DEVICE;

	if (vma->vm_flags == (VM_READ | VM_WRITE))
		dir = DMA_BIDIRECTIONAL;

	mutex_lock(&smaf_dev.lock);
	smaf_revoke_access(handle, get_cpu_device(0), 0, handle->length, dir);
	mutex_unlock(&smaf_dev.lock);
}

static const struct vm_operations_struct smaf_vma_ops = {
	.close = smaf_vm_close,
};

static int smaf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct smaf_handle *handle = dmabuf->priv;
	bool ret;
	enum dma_data_direction dir;

	if (smaf_allocate(handle, dmabuf))
		return -EINVAL;

	vma->vm_private_data = handle;
	vma->vm_ops = &smaf_vma_ops;

	if (vma->vm_flags == VM_READ)
		dir = DMA_TO_DEVICE;

	if (vma->vm_flags == VM_WRITE)
		dir = DMA_FROM_DEVICE;

	if (vma->vm_flags == (VM_READ | VM_WRITE))
		dir = DMA_BIDIRECTIONAL;

	mutex_lock(&smaf_dev.lock);
	ret = smaf_grant_access(handle, get_cpu_device(0), 0,
				handle->length, dir);
	mutex_unlock(&smaf_dev.lock);

	if (!ret)
		return -EINVAL;

	return dma_buf_mmap(handle->db_alloc, vma, 0);
}

static void smaf_dma_buf_release(struct dma_buf *dmabuf)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (handle->db_alloc)
		dma_buf_put(handle->db_alloc);

	mutex_lock(&smaf_dev.lock);
	smaf_unsecure_handle(handle);
	mutex_unlock(&smaf_dev.lock);

	kfree(handle);
}

static int smaf_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					 enum dma_data_direction dir)
{
	struct smaf_handle *handle = dmabuf->priv;
	bool ret;

	if (!handle->db_alloc)
		return -EINVAL;

	mutex_lock(&smaf_dev.lock);
	ret = smaf_grant_access(handle,
				get_cpu_device(0), 0, handle->length, dir);
	mutex_unlock(&smaf_dev.lock);

	if (!ret)
		return -EINVAL;

	return dma_buf_begin_cpu_access(handle->db_alloc, dir);
}

static int smaf_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				       enum dma_data_direction dir)
{
	struct smaf_handle *handle = dmabuf->priv;
	int ret;

	if (!handle->db_alloc)
		return -EINVAL;

	ret = dma_buf_end_cpu_access(handle->db_alloc, dir);

	mutex_lock(&smaf_dev.lock);
	smaf_revoke_access(handle, get_cpu_device(0), 0, handle->length, dir);
	mutex_unlock(&smaf_dev.lock);

	return ret;
}

static void *smaf_dma_buf_kmap_atomic(struct dma_buf *dmabuf,
				      unsigned long offset)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return NULL;

	return dma_buf_kmap_atomic(handle->db_alloc, offset);
}

static void smaf_dma_buf_kunmap_atomic(struct dma_buf *dmabuf,
				       unsigned long offset, void *ptr)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return;

	dma_buf_kunmap_atomic(handle->db_alloc, offset, ptr);
}

static void *smaf_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return NULL;

	return dma_buf_kmap(handle->db_alloc, offset);
}

static void smaf_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
				void *ptr)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return;

	dma_buf_kunmap(handle->db_alloc, offset, ptr);
}

static void *smaf_dma_buf_vmap(struct dma_buf *dmabuf)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return NULL;

	return dma_buf_vmap(handle->db_alloc);
}

static void smaf_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!handle->db_alloc)
		return;

	dma_buf_vunmap(handle->db_alloc, vaddr);
}

static int smaf_attach(struct dma_buf *dmabuf, struct device *dev,
		       struct dma_buf_attachment *attach)
{
	struct smaf_handle *handle = dmabuf->priv;
	struct dma_buf_attachment *db_attach;

	if (!handle->db_alloc)
		return 0;

	db_attach = dma_buf_attach(handle->db_alloc, dev);

	return IS_ERR(db_attach);
}

static void smaf_detach(struct dma_buf *dmabuf,
			struct dma_buf_attachment *attach)
{
	struct smaf_handle *handle = dmabuf->priv;
	struct dma_buf_attachment *db_attachment;

	if (!handle->db_alloc)
		return;

	db_attachment = smaf_find_attachment(handle->db_alloc, attach->dev);
	dma_buf_detach(handle->db_alloc, db_attachment);
}

static const struct dma_buf_ops smaf_dma_buf_ops = {
	.attach = smaf_attach,
	.detach = smaf_detach,
	.map_dma_buf = smaf_map_dma_buf,
	.unmap_dma_buf = smaf_unmap_dma_buf,
	.mmap = smaf_mmap,
	.release = smaf_dma_buf_release,
	.begin_cpu_access = smaf_dma_buf_begin_cpu_access,
	.end_cpu_access = smaf_dma_buf_end_cpu_access,
	.kmap_atomic = smaf_dma_buf_kmap_atomic,
	.kunmap_atomic = smaf_dma_buf_kunmap_atomic,
	.kmap = smaf_dma_buf_kmap,
	.kunmap = smaf_dma_buf_kunmap,
	.vmap = smaf_dma_buf_vmap,
	.vunmap = smaf_dma_buf_vunmap,
};

static bool is_smaf_dmabuf(struct dma_buf *dmabuf)
{
	return dmabuf->ops == &smaf_dma_buf_ops;
}

bool smaf_is_secure(struct dma_buf *dmabuf)
{
	struct smaf_handle *handle = dmabuf->priv;

	if (!is_smaf_dmabuf(dmabuf))
		return false;

	return atomic_read(&handle->is_secure);
}
EXPORT_SYMBOL(smaf_is_secure);

int smaf_set_secure(struct dma_buf *dmabuf, bool secure)
{
	struct smaf_handle *handle = dmabuf->priv;
	int ret;

	if (!is_smaf_dmabuf(dmabuf))
		return -EINVAL;

	mutex_lock(&smaf_dev.lock);
	if (secure)
		ret = smaf_secure_handle(handle);
	else
		ret = smaf_unsecure_handle(handle);
	mutex_unlock(&smaf_dev.lock);

	return ret;
}
EXPORT_SYMBOL(smaf_set_secure);

static int smaf_select_allocator_by_name(struct dma_buf *dmabuf, char *name)
{
	struct smaf_handle *handle = dmabuf->priv;
	struct smaf_allocator *alloc;

	if (!is_smaf_dmabuf(dmabuf))
		return -EINVAL;

	if (handle->allocator)
		return -EINVAL;

	mutex_lock(&smaf_dev.lock);

	list_for_each_entry(alloc, &smaf_dev.head, list_node) {
		if (!strncmp(alloc->name, name, MAX_NAME_LENGTH)) {
			handle->allocator = alloc;
			handle->db_alloc = NULL;
		}
	}

	mutex_unlock(&smaf_dev.lock);

	if (!handle->allocator)
		return -EINVAL;

	return 0;
}

static struct smaf_handle *smaf_create_handle(size_t length, unsigned int flags)
{
	struct smaf_handle *handle;

	DEFINE_DMA_BUF_EXPORT_INFO(info);

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return NULL;

	info.ops = &smaf_dma_buf_ops;
	info.size = round_up(length, PAGE_SIZE);
	info.flags = flags;
	info.priv = handle;

	handle->dmabuf = dma_buf_export(&info);
	if (IS_ERR(handle->dmabuf)) {
		kfree(handle);
		return NULL;
	}

	handle->length = info.size;
	handle->flags = flags;

	return handle;
}

static long smaf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SMAF_IOC_CREATE:
	{
		struct smaf_create_data data;
		struct smaf_handle *handle;

		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;

		if (data.version != 0)
			return -EINVAL;

		if (data.flags & ~(SMAF_RDWR | SMAF_CLOEXEC))
			return -EINVAL;

		handle = smaf_create_handle(data.length, data.flags);
		if (!handle)
			return -EINVAL;

		if (data.name[0]) {
			data.name[MAX_NAME_LENGTH - 1] = 0;
			/* user force allocator selection */
			if (smaf_select_allocator_by_name(handle->dmabuf,
							  data.name)) {
				dma_buf_put(handle->dmabuf);
				return -EINVAL;
			}
		}

		handle->fd = dma_buf_fd(handle->dmabuf, data.flags);
		if (handle->fd < 0) {
			dma_buf_put(handle->dmabuf);
			return -EINVAL;
		}

		data.fd = handle->fd;
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
			dma_buf_put(handle->dmabuf);
			return -EFAULT;
		}
		break;
	}
	case SMAF_IOC_GET_SECURE_FLAG:
	{
		struct smaf_secure_flag data;
		struct dma_buf *dmabuf;

		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;

		if (data.version != 0)
			return -EINVAL;

		if (data.fd == -1)
			return -EINVAL;

		dmabuf = dma_buf_get(data.fd);
		if (!dmabuf)
			return -EINVAL;

		data.secure = smaf_is_secure(dmabuf);
		dma_buf_put(dmabuf);

		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}
	case SMAF_IOC_SET_SECURE_FLAG:
	{
		struct smaf_secure_flag data;
		struct dma_buf *dmabuf;
		int ret;

		if (!smaf_dev.secure)
			return -EINVAL;

		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;

		if (data.version != 0)
			return -EINVAL;

		dmabuf = dma_buf_get(data.fd);
		if (!dmabuf)
			return -EINVAL;

		ret = smaf_set_secure(dmabuf, data.secure);

		dma_buf_put(dmabuf);

		if (ret)
			return -EINVAL;

		break;
	}
	case SMAF_IOC_GET_INFO:
	{
		struct smaf_info info;
		struct smaf_allocator *alloc;

		if (copy_from_user(&info, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;

		if (info.version != 0)
			return -EINVAL;

		info.count = 0;
		list_for_each_entry(alloc,  &smaf_dev.head, list_node) {
			if (info.count++ == info.index) {
				strncpy(info.name, alloc->name,
					MAX_NAME_LENGTH);
				info.name[MAX_NAME_LENGTH - 1] = 0;
			}
		}

		if (info.index >= info.count)
			return -EINVAL;

		if (copy_to_user((void __user *)arg, &info, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}
	default:
		return -EINVAL;
	}

	return 0;
}

static int __init smaf_init(void)
{
	int ret;

	ret = misc_register(&smaf_dev.misc_dev);
	if (ret < 0)
		return ret;

	mutex_init(&smaf_dev.lock);
	INIT_LIST_HEAD(&smaf_dev.head);

	return ret;
}
module_init(smaf_init);

static void __exit smaf_deinit(void)
{
	misc_deregister(&smaf_dev.misc_dev);
}
module_exit(smaf_deinit);

MODULE_DESCRIPTION("Secure Memory Allocation Framework");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Benjamin Gaignard <benjamin.gaignard@linaro.org>");

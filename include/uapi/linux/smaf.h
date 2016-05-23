/*
 * smaf.h
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 */

#ifndef _UAPI_SMAF_H_
#define _UAPI_SMAF_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define MAX_NAME_LENGTH 64

#define SMAF_RDWR O_RDWR
#define SMAF_CLOEXEC O_CLOEXEC

/**
 * struct smaf_create_data - allocation parameters
 * @version:	structure version (must be set to 0)
 * @length:	size of the requested buffer
 * @flags:	mode flags for the file like SMAF_RDWR or SMAF_CLOEXEC
 * @fd:		returned file descriptor
 * @name:	name of the allocator to be selected
 *		when NULL smaf will iterate over allocator to find
 *		one matching with devices constraints.
 */
struct smaf_create_data {
	__u64 version;
	__u64 length;
	__u32 flags;
	__u32 reserved1;
	__s32 fd;
	__u32 reserved2;
	__u8 name[MAX_NAME_LENGTH];
	__u8 reserved3[32];
};

/**
 * struct smaf_secure_flag - set/get secure flag
 * @version:	structure version (must be set to 0)
 * @fd:		file descriptor
 * @secure:	secure flag value (set or get)
 */
struct smaf_secure_flag {
	__u64 version;
	__s32 fd;
	__u32 reserved1;
	__u32 secure;
	__u8 reserved2[44];
};

/**
 * struct smaf_info - get registered allocator name per index
 * @version:	structure version (must be set to 0)
 * @index:	allocator's index
 * @count:	return number of registered allocators
 * @name:	return allocator name
 */
struct smaf_info {
	__u64 version;
	__u32 index;
	__u32 reserved1;
	__u32 count;
	__u32 reserved2;
	__u8 name[MAX_NAME_LENGTH];
	__u8 reserved3[40];
};

#define SMAF_IOC_MAGIC	'S'

#define SMAF_IOC_CREATE		 _IOWR(SMAF_IOC_MAGIC, 0, \
				       struct smaf_create_data)

#define SMAF_IOC_GET_SECURE_FLAG _IOWR(SMAF_IOC_MAGIC, 1, \
				       struct smaf_secure_flag)

#define SMAF_IOC_SET_SECURE_FLAG _IOWR(SMAF_IOC_MAGIC, 2, \
				       struct smaf_secure_flag)

#define SMAF_IOC_GET_INFO	 _IOWR(SMAF_IOC_MAGIC, 3, struct smaf_info)

#endif

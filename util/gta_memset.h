/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#ifndef __GTA_MEMSET__

#define RSIZE_MAX (SIZE_MAX>>1)
typedef size_t rsize_t;
typedef int errno_t;

errno_t gta_memset(void *s, rsize_t smax, int c, rsize_t n);

#endif /*  __GTA_MEMSET__ */


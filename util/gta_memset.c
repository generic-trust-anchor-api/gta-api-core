/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/
/*
 * Re-implementation of memset_s from the C11 Standard / Annex K
 *
 * Notes:
 * The function name was changed to prevent naming conflicts.
 * The C11 exception handling is not used in contrast to a fully C11
 *    compliant implementation.
 * The routine could be directly replaced by a call to memset_s where
 *    available.
 * The use of intermediate volatile variables should prevent optimizations
 *    that can lead to a removal of the operation.
 *
 * The code is inspired by the implementation in FreeBSD,
 * see https://github.com/freebsd/freebsd-src.git, lib/libc/string/memset_s.c
 *
 * Copyright (c) 2017 Juniper Networks.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gta_memset.h"

errno_t gta_memset(void *s, rsize_t smax, int c, rsize_t n)
{
    errno_t ret = EINVAL;
    rsize_t lim = 0;
    unsigned char v;
    volatile unsigned char *dst;

    if (n < smax) {
        lim = n;
    }
    else {
        lim = smax;
    }

    v = (unsigned char)c;
    dst = (unsigned char *)s;

    if ((s != NULL) && (smax <= RSIZE_MAX) && (n <= RSIZE_MAX)) {
        while (lim > 0) {
            dst[--lim] = v;
        }
        if (n <= smax) {
            ret = 0;
        }
    }
    return ret;
}


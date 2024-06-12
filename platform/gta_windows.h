/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef GTA_WINDOWS_H
#define GTA_WINDOWS_H

#if _MSC_VER > 1000
 /* microsoft */
 /* Specifies that the file will be included (opened) only
    once by the compiler in a build. This can reduce build
    times as the compiler will not open and read the file
    after the first #include of the module. */
#pragma once
#endif

#if defined(__cplusplus)
    /* *INDENT-OFF* */
extern "C"
{
    /* *INDENT-ON* */
#endif

/*---------------------------------------------------------------------*/

#include <gta_api.h>

gta_mutex_t gta_windows_mutex_create();
bool gta_windows_mutex_destroy(gta_mutex_t mutex);
bool gta_windows_mutex_lock(gta_mutex_t mutex);
bool gta_windows_mutex_unlock(gta_mutex_t mutex);

/*---------------------------------------------------------------------*/

#if defined(__cplusplus)
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* GTA_WINDOWS_H */

/*** end of file ***/

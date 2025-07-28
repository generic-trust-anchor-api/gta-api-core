/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef GTA_LINUX_H
#define GTA_LINUX_H

#if defined(__cplusplus)
    /* *INDENT-OFF* */
extern "C"
{
    /* *INDENT-ON* */
#endif

/*---------------------------------------------------------------------*/

#include <gta_api.h>

gta_mutex_t gta_linux_mutex_create();
bool gta_linux_mutex_destroy(gta_mutex_t mutex);
bool gta_linux_mutex_lock(gta_mutex_t mutex);
bool gta_linux_mutex_unlock(gta_mutex_t mutex);

/*---------------------------------------------------------------------*/

#if defined(__cplusplus)
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* GTA_LINUX_H */

/*** end of file ***/

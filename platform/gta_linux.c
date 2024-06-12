/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include <gta_api.h>
#include "gta_linux.h"
#include <stdlib.h>
#include <pthread.h>

GTA_DEFINE_FUNCTION(gta_mutex_t, gta_linux_mutex_create, ())
{
    pthread_mutex_t * p_mutex = NULL;

    p_mutex = malloc(sizeof(pthread_mutex_t));
    if (NULL != p_mutex) {
        if (0 != pthread_mutex_init(p_mutex, NULL)) {
            free(p_mutex);
            p_mutex = NULL;
        }
    }

    return ((gta_mutex_t)p_mutex);
}

GTA_DEFINE_FUNCTION(bool, gta_linux_mutex_destroy,
(
    gta_mutex_t mutex
))
{
    bool b_ret = false;

    if ((GTA_HANDLE_INVALID != mutex) 
        && (0 == pthread_mutex_destroy(mutex))){

        b_ret = true;
        free(mutex);
    }

    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_linux_mutex_lock,
(
    gta_mutex_t mutex
))
{
    bool b_ret = false;

    if ((GTA_HANDLE_INVALID != mutex)
        && (0 == pthread_mutex_lock(mutex))){

        b_ret = true;
    }

    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_linux_mutex_unlock,
(
    gta_mutex_t mutex
))
{
    bool b_ret = false;

    if ((GTA_HANDLE_INVALID != mutex)
        && (0 == pthread_mutex_unlock(mutex))){
        b_ret = true;
    }

    return b_ret;
}

 /*** end of file ***/

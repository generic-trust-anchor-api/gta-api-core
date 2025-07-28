/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include <windows.h>

#include <gta_api.h>
#include "gta_windows.h"

GTA_DEFINE_FUNCTION(gta_mutex_t, gta_windows_mutex_create, ())
{
    HANDLE h_mutex;

    h_mutex = CreateMutex(NULL, FALSE, NULL);

    return h_mutex;
}

GTA_DEFINE_FUNCTION(bool, gta_windows_mutex_destroy,
(
    gta_mutex_t mutex
))
{
    if (CloseHandle((HANDLE)(mutex))) return true;

    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_windows_mutex_lock,
(
    gta_mutex_t mutex
))
{
    DWORD wait_result;

    wait_result = WaitForSingleObject((HANDLE)(mutex), INFINITE);

    if (WAIT_OBJECT_0 == wait_result) return true;

    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_windows_mutex_unlock,
(
    gta_mutex_t mutex
))
{
    if (ReleaseMutex((HANDLE)(mutex))) return true;

    return false;
}

 /*** end of file ***/

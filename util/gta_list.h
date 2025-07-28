/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef LIST_H
#define LIST_H

#if defined (_MSC_VER) && (_MSC_VER > 1000)
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

#include <stdbool.h>

struct list_t {
    void * p_next;  /* pointer to the next list_t on the list;
                       NULL indicates end of list */
};

/* @brief Compare two items of a list. */
typedef bool(*list_item_cmp)(void * p_item, void * p_item_crit);

/* @brief Free resources hold by an item stored on a list. */
typedef void(*list_item_free)(void * p_item);

/* @brief Append new element at the end of list. */
void
list_append(struct list_t ** pp_head, void * p_item);

/* @brief Append new element at front of list. */
void
list_append_front(struct list_t ** pp_head, void * p_item);

/* @brief Remove element at front of list.
   Returns pointer to the removed element or NULL in case the list is empty. */
void *
list_remove_front(struct list_t ** pp_head);

/* @brief Get element at index (1..list_cnt())
   Returns pointer to list element or NULL. */
void *
list_get(struct list_t * p_head, size_t index);

/* @brief Returns the number of elements currently stored in the list. */
size_t
list_cnt(struct list_t * p_head);

/* @brief Remove element from list.
   Returns pointer to the element unlinked from the list
   on success or NULL. */
void *
list_remove(struct list_t ** pp_head, void * p_item, list_item_cmp cmp);

/* @brief Find element in list.
   Returns pointer to matching item on success or NULL. */
void *
list_find(struct list_t * p_head, void * p_item_crit, list_item_cmp cmp);

#if defined(__cplusplus)
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* LIST_H */

/*** end of file ***/

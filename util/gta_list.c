/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include <stddef.h>

#include "gta_list.h"


/* @brief Append new element at the end of list. */
void
list_append(struct list_t ** pp_head, void * p_item)
{
    if (NULL == *pp_head) {
        *pp_head = p_item;
    } else {
        struct list_t * last = *pp_head;
        while (last->p_next != NULL) {
            last = last->p_next;
        }
        last->p_next = p_item;
    }

}


/* @brief Append element at front of list. */
void
list_append_front(struct list_t ** pp_head, void * p_item)
{
    ((struct list_t *)p_item)->p_next = *pp_head;
    *pp_head = p_item;
}


/* @brief Remove element at front of list.
   Returns pointer to the removed element or NULL in case the list is empty. */
void *
list_remove_front(struct list_t ** pp_head)
{
    struct list_t * p_front = NULL;

    if (*pp_head)
    {
        p_front = ((struct list_t *)*pp_head);
        if (p_front) *pp_head = p_front->p_next;
    }

    return p_front;
}


/* @brief Get element at index (1..list_cnt())
   Returns pointer to list element or NULL. */
void *
list_get(struct list_t * p_head, size_t index)
{
    struct list_t * p_item = p_head;

    while (--index > 0)
    {
        if (p_item) p_item = p_item->p_next;
        else break;
    }

    return p_item;
}


/* @brief Returns the number of elements currently stored in the list. */
size_t
list_cnt(struct list_t * p_head)
{
    struct list_t * p_item = (struct list_t *)p_head;
    size_t cnt = 0;

    while (p_item) {
        p_item = p_item->p_next;
        cnt++;
    }

    return cnt;
}


/* @brief Find an element stored in the list.
   Returns a pointer to the element or NULL.  */
void *
list_find(struct list_t * p_head, void * p_item_crit, list_item_cmp cmp)
{
    while (NULL != p_head) {
        if (cmp(p_head, p_item_crit)) {
            return p_head;
        }
        p_head = ((struct list_t *)p_head)->p_next;
    }

    return NULL;
}


/* @brief Remove element from list.
   Returns new value for p_head or NULL. */
void *
list_remove(struct list_t ** pp_head, void * p_item, list_item_cmp cmp)
{
    struct list_t * p_list0 = NULL;
    struct list_t * p_list1 = *pp_head;

    while (NULL != p_list1) {
        if (cmp(p_list1, p_item)) {
            if (p_list0) {
                p_list0->p_next = p_list1->p_next;
            }
            else {
                /* remove first list element */
                *pp_head = p_list1->p_next;
            }
            return p_list1;
        }
        p_list0 = p_list1;
        p_list1 = p_list1->p_next;
    }

    return NULL;
}

 /*** end of file ***/

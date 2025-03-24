/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <stdarg.h>

#include <gta_api.h>
#include <gta_secmem.h>
#ifdef WINDOWS
//#   define _CRTDBG_MAP_ALLOC
#   include <stdlib.h>
#   include <crtdbg.h>
#   include <gta_windows.h>
#endif /* WINDOWS */

#include <gta_list.h>
#include <gta_memset.h>

#define NULL_PTR ((void*)0)

#define THREADS 0

/* Declare a GTA API provider forward function body for function_name. */
#define GTA_PROVIDER_FWD_FUNCTION(p_provider, function_name, parameter_list) \
    (((p_provider)->function_list->pf_ ## function_name) != NULL) \
    ? ((p_provider)->function_list->pf_ ## function_name parameter_list) \
    : ((*p_errinfo = GTA_ERROR_PROVIDER_INVALID) != GTA_ERROR_PROVIDER_INVALID)

/* Use an internal map to lookup context object pointers by handle.
 * This option is currently disabled since it comes with some linkage issues:
 * In case a context handle needs to be resolved by a GTA provider the
 * provider might be linked to a different instance of the GTA library
 * than the application itself (e.g., static linkage of the provider).
 * In this scenario it is not clear, whether both instances would share
 * the same (global) handle map. Linkage is also platform dependant.
 *
 *       +-----+     +-----+     +----------+     +-----+
 *       | App |---->| GTA |---->| GTA Prov |---->| GTA |
 *       +-----+     +-----+     +----------+     +-----+
 *                      |                            |
 *                 g_handle_map ---------------------?
 *
 * Responsibility for the initialization of g_handle_map is also an issue.
 * Currently the context object pointer is simply cast to gta_handle_t.
 */
#define GTA_HANDLE_MAP 1
#define GTA_HANDLE_MAP_SIZE 40

/* Handle management

   @todo Sharing handles accross multiple threads is not yet supported.
   In case a handle aquired by thread A is used by thread B the result
   is undefined. */

typedef enum {
    GTA_HANDLE_TYPE_INVALID = 0,
    GTA_HANDLE_TYPE_INSTANCE = 1,
    GTA_HANDLE_TYPE_INSTANCE_PROVIDER = 2,
    GTA_HANDLE_TYPE_CONTEXT = 3,
    GTA_HANDLE_TYPE_ACCESS_POLICY = 4,
    GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE = 5,
    GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR = 6,
    GTA_HANDLE_TYPE_FRAMEWORK_ENUM = 7,
} gta_handle_type_t;

typedef struct object object_t;

/* TODO: double-check if this solution works with multiple instances */
const char * no_mutex = "no_mutex_pointer";
#define GTA_NO_MUTEX_PTR ((gta_mutex_t)no_mutex)

typedef struct {
    gta_handle_type_t type;
    void *p;
} handle_map_entry_t;
struct {
    bool initialized;
    /* map of valid handles to ptrs */
    handle_map_entry_t map[GTA_HANDLE_MAP_SIZE +
        1 /* index 0 is reserved */];
    /* cyclic list of free handles
       The cyclic list maximizes the time for which a handle value
       stays invalid after being released before the handle value is
       reused. */
    gta_handle_t free[GTA_HANDLE_MAP_SIZE + 1];
    size_t get;                 /* start of cyclic list - get new handles from here */
    size_t release;             /* end of cyclic list - put released handles here */
} g_handle_map = { 0 };

static gta_handle_t
alloc_handle(gta_handle_type_t type, void *params,
             void **p_ptr, gta_errinfo_t * p_errinfo);

static bool
free_handle(gta_handle_t h, gta_errinfo_t * p_errinfo);


/* single element of a linked list used for secure memory management */
struct secmem_block_t {
    struct secmem_block_t * p_next;
    void * ptr;
    size_t n;
    size_t size;
};

struct profile_list_item_t {
    struct profile_list_item_t * p_next;

    gta_profile_name_t profile_name;
    struct provider_list_item_t * p_provider;
};

struct provider_list_item_t {
    struct provider_list_item_t * p_next;

    gta_context_handle_t h_ctx;
    const struct gta_function_list_t * function_list;

    /* provider specific context parameters */
    void * p_provider_params;
    /* callback to cleanup provider specific parameters */
    void (*pf_free_params)(void *);
    /* Information used to uniquely identify a provider */
    void * uid;
};


/* internal instance description */
typedef struct {
    const struct gta_instance_params_t params;

    struct provider_list_item_t * p_provider_list;
    struct profile_list_item_t * p_profile_list;

    /* output stream that can be used for logging */
    gtaio_ostream_t * logging;

    /* static handles for predefined simple access_policies */
    gta_access_policy_handle_t h_access_policy_simple_initial;
    gta_access_policy_handle_t h_access_policy_simple_basic;
    gta_access_policy_handle_t h_access_policy_simple_physical_presence;
} instance_object_t;


/* this object is used to associate an instance with a specific provider

   Instance_provider_object_t is used to wrap an instance handle before
   h_inst is forwarded to a provider function. This allows to determine the
   provider which issued a call using h_inst. */
struct instance_provider_object_t {
    instance_object_t * p_inst_obj;
    gta_instance_handle_t h_inst;
    struct provider_list_item_t * p_provider;
};

static struct framework_enum_object_t *
check_framework_enum_handle(
    gta_enum_handle_t h_enum,
    gta_errinfo_t * p_errinfo);

static object_t *
create_framework_enum_object(
    instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo);

static bool
destroy_framework_enum_object(
    struct framework_enum_object_t * p_framework_enum_obj,
    gta_errinfo_t * p_errinfo);

/*
   Framework_enum_object_t is used to combine an enum handle which is forwarded
   to a provider during enumeration functions with a provider_list_item_t. This
   allows to extend the enumeration operations over all registered providers on
   framework level. */
struct framework_enum_object_t {
    instance_object_t * p_inst_obj;
    struct provider_list_item_t * p_provider;
    gta_enum_handle_t h_enum;
};

static object_t *
create_instance_object(
    const struct gta_instance_params_t * p_params,
    gta_errinfo_t * p_errinfo);

static bool
destroy_instance_object(
    instance_object_t * p_ctx_obj,
    gta_errinfo_t * p_errinfo);

/* Validate the given handle and return pointer to the managed object. */
static instance_object_t *
check_instance_handle(gta_instance_handle_t h_ctx, gta_errinfo_t * p_errinfo);


/* internal context description */
typedef struct context_object_t {
    /* GTA API instance to which this context belongs */
    instance_object_t * p_inst_obj;
    /* provider to which the context belongs */
    struct provider_list_item_t * p_provider;
    /* single linked list of memory blocks allocated using gta_secmem_alloc() */
    struct secmem_block_t * p_secmem_first;
    /* context specific params */
    void * p_context_params;
} context_object_t;

static object_t *
create_context_object(
    instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo);

static bool
destroy_context_object(context_object_t * p_ctx_obj, gta_errinfo_t * p_errinfo);

/* Validate the given handle and return pointer to the managed object. */
static context_object_t *
check_context_handle(gta_context_handle_t h_ctx, gta_errinfo_t * p_errinfo);

#if 0 /* @todo sanitize enum handles */

/* internal enum description object */
typedef struct {
    gta_handle_t h_depend; /* Handle to the context to which the
                              enumeration belongs. This information is
                              required to purge pending enumerations in
                              case the context goes away. */
    list_t * p_index;      /* pointer to current list object */
} enum_object_t;


static object_t *
create_enum_object(instance_object_t * p_inst_obj, gta_errinfo_t * p_errinfo);

static bool
destroy_enum_object(context_object_t * p_ctx_obj, gta_errinfo_t * p_errinfo);

/* Validate the given handle and return pointer to the managed object. */
static enum_object_t *
check_enum_handle(gta_context_handle_t h_ctx, gta_errinfo_t * p_errinfo);

#else

/* Validate the given handle and return pointer to the managed object. */
// FIXME this prototype causes an compile error with GCC. The error states that a incompatible redefinition was done. It is not clear why this fails
//static void *
//check_enum_handle(gta_enum_handle_t h_ctx, struct list_t * p_head, gta_errinfo_t * p_errinfo);

#endif


/* internal access token descriptor
   access token descriptors are managed in a linked list */
struct access_token_descriptor_object_list_item_t {
    struct access_token_descriptor_object_list_item_t * p_next;

    /* the access policy to which this token descriptor belongs */
    struct access_policy_object_t * p_access_policy_obj;
    /* self reference to this token descriptor object
       required for gta_access_policy_enumerate() */
    gta_access_descriptor_handle_t h_self;

    gta_access_descriptor_type_t type;
    struct {
        gta_personality_fingerprint_t pers_fingerprint;
        gta_profile_name_t profile_name;
    } pers_derived;
};


/* internal access policy description */
struct access_policy_object_t {
    instance_object_t * p_inst_obj;  /* GTA API instance to which this
                                        access policy belongs */

    /* list of access token descriptors */
    struct access_token_descriptor_object_list_item_t * p_access_token_descriptor_list;

    /* There can be only one initial and one basic access token.
       These pointers provide a shortcut into the access token
       descriptor list. initial_access_token_descriptor.p_next and
       basic_access_token_descriptor.p_next must not be used. */
    struct access_token_descriptor_object_list_item_t * p_initial_access_token_descriptor;
    struct access_token_descriptor_object_list_item_t * p_basic_access_token_descriptor;
};

static object_t *
create_access_policy_object(
    instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo);

static bool
destroy_access_policy_object(
    struct access_policy_object_t * p_access_policy_obj,
    gta_errinfo_t * p_errinfo);

#if 0
static bool
destroy_access_policy_object_simple(
    access_policy_object_t * p_access_policy_obj,
    gta_errinfo_t * p_errinfo);
#endif

static object_t *
create_access_token_descriptor_object(
    struct access_policy_object_t * p_access_policy_object,
    gta_errinfo_t * p_errinfo);

static bool
destroy_access_token_descriptor_object(
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object,
    gta_errinfo_t * p_errinfo);

static struct access_token_descriptor_object_list_item_t *
check_access_token_descriptor_handle(
    gta_access_descriptor_handle_t h_access_token_descriptor,
    gta_errinfo_t * p_errinfo);

/* Validate the given access_policy handle and return pointer to the
   managed object.
   simple indicates whether access policies constructed from a
   "simple" access policy descriptor are taken into account or not. */
static const struct access_policy_object_t *
check_access_policy_handle(
    gta_context_handle_t h_access_policy,
    bool simple,
    gta_errinfo_t * p_errinfo);


bool
init_g_handle_map()
{
    bool b_ret = true;

    if (false == g_handle_map.initialized) {
        size_t i = 0;
        while (i <= GTA_HANDLE_MAP_SIZE)
        {
            g_handle_map.map[i].p = NULL_PTR;
            g_handle_map.free[i] = (gta_handle_t)i;
            i++;
        }
        g_handle_map.get = 1;
        g_handle_map.release = 1;
        g_handle_map.initialized = true;
    }

    return b_ret;
}

/*
 * Helper function intended to be used at the beginning of each framework
 * function to check the pointer p_errinfo and optionally a variable number of
 * additional pointers against NULL. The functions returns false in case one of
 * the pointers is NULL, true otherwise.
 * If the function returns false and p_errinfo is not NULL, p_errinfo is set to
 * GTA_ERROR_INVALID_PARAMETER.
 */

#define basic_pointer_validation(p_errinfo, ...) \
    basic_pointer_validation_internal(p_errinfo, \
        (sizeof((const void*[]) { NULL, __VA_ARGS__ }) / sizeof(void*)), \
        (const void*[]) { NULL, __VA_ARGS__ })

/* As __VA_ARGS__ can be empty, which would cause a compiler warning for the
 * function call "basic_pointer_validation_internal", we add "NULL" as first
 * element of the list. This needs to be considered when walking trough the
 * list. */
static bool
basic_pointer_validation_internal(gta_errinfo_t * p_errinfo, size_t n_pointer, const void ** pointer_to_check)
{
    bool b_ret = false;
    size_t checkcounter = 1;

    for (size_t i=1; i<n_pointer; ++i) {
        if (NULL != pointer_to_check[i]) {
            ++checkcounter;
        }
    }
    if ((n_pointer==checkcounter) && (NULL != p_errinfo)) {
        b_ret = true;
    }
    else {
        if (NULL != p_errinfo) {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        }
    }
    return b_ret;
}

static bool
provider_uid_cmp(void * p_provider_list_item, void * p_uid);

static bool
profile_name_cmp(void * p_profile_list_item, void * p_profile_name);

/* Implementation specific boundary of profile name length */
#define PROFILE_NAME_LENGTH_MAX 1024

GTA_DEFINE_FUNCTION(bool, gta_register_provider,
(
    gta_instance_handle_t h_inst,
    const struct gta_provider_info_t * p_provider_info,
    gta_errinfo_t * p_errinfo
    ))
{
    bool b_ret = false;
    instance_object_t * p_inst_obj;
    context_object_t * p_ctx_obj;
    size_t profile_name_length = 0;

    if (true != basic_pointer_validation(p_errinfo, p_provider_info)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (p_inst_obj) {
        if (GTA_PROVIDER_INFO_CALLBACK == p_provider_info->type)
        {
            if (NULL == p_provider_info->profile_info.profile_name) {
                *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
                goto err;
            }

            struct provider_list_item_t * p_provider_list_item;

/* Avoid GCC warning regarding forbidden pointer conversion */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
            /* Check if the same provider has been registered already */
            p_provider_list_item = list_find((struct list_t *)(p_inst_obj->p_provider_list), (void *)(p_provider_info->provider_init), provider_uid_cmp);
#pragma GCC diagnostic pop

            if (NULL == p_provider_list_item) {
                /* First registration of the provider: create internal structures */
                p_provider_list_item = p_inst_obj->params.os_functions.calloc(1, sizeof(struct provider_list_item_t));
                if (NULL != p_provider_list_item) {
                    p_provider_list_item->h_ctx = alloc_handle(GTA_HANDLE_TYPE_CONTEXT, p_inst_obj, (void **)(&p_ctx_obj), p_errinfo);
                    if (NULL != p_provider_list_item->h_ctx) {
                        p_ctx_obj->p_provider = p_provider_list_item;
                        p_provider_list_item->function_list = p_provider_info->provider_init(
                            p_provider_list_item->h_ctx,
                            p_provider_info->provider_init_config,
                            p_inst_obj->logging,
                            &(p_provider_list_item->p_provider_params),
                            &(p_provider_list_item->pf_free_params),
                            p_errinfo);
                        /* Check if provider_init() returned a function_list and
                         * pf_free_params (mandatory) */
                        if ((NULL == p_provider_list_item->function_list) ||
                            (NULL == p_provider_list_item->pf_free_params)) {
                            /* cleanup */
                            free_handle(p_provider_list_item->h_ctx, p_errinfo);
                            p_inst_obj->params.os_functions.free(p_provider_list_item);
                            *p_errinfo = GTA_ERROR_PROVIDER_INVALID;
                            goto err;
                        }
                        /*
                         * At this point the registration of a new provider was
                         * successful. It will not be cleaned up in case an
                         * error happens during the registration of the profile
                         */
/* Avoid GCC warning regarding forbidden pointer conversion */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
                        p_provider_list_item->uid = (void *)p_provider_info->provider_init;
#pragma GCC diagnostic pop
                        list_append_front((struct list_t **)&(p_inst_obj->p_provider_list), p_provider_list_item);
                    }
                    else {
                        /* Free memory for p_provider_list_item */
                        p_inst_obj->params.os_functions.free(p_provider_list_item);
                        goto err;
                    }
                }
                else {
                    *p_errinfo = GTA_ERROR_MEMORY;
                    goto err;
                }
            }
            /*
             * Search profile in profile list and add the profile to the list if
             * not yet there, otherwise fail.
             * todo(thomas.zeschg): implement priorities as defined in spec.
             */
            struct profile_list_item_t * p_profile_list_item;

            p_profile_list_item = list_find((struct list_t *)(p_inst_obj->p_profile_list), p_provider_info->profile_info.profile_name, profile_name_cmp);
            if (NULL == p_profile_list_item) {
                /* Add profile to list */
                p_profile_list_item = p_inst_obj->params.os_functions.calloc(1, sizeof(struct profile_list_item_t));
                if (NULL != p_profile_list_item) {
                    profile_name_length = strnlen(p_provider_info->profile_info.profile_name, PROFILE_NAME_LENGTH_MAX);
                    if ((0 != profile_name_length) && (PROFILE_NAME_LENGTH_MAX != profile_name_length)) {
                        p_profile_list_item->profile_name = p_inst_obj->params.os_functions.calloc(1, profile_name_length + 1);
                        if (NULL != p_profile_list_item->profile_name) {
                            memcpy(p_profile_list_item->profile_name, p_provider_info->profile_info.profile_name, profile_name_length + 1);
                            p_profile_list_item->p_provider = p_provider_list_item;
                            list_append_front((struct list_t **)&(p_inst_obj->p_profile_list), p_profile_list_item);
                            b_ret=true;
                        }
                        else {
                            p_inst_obj->params.os_functions.free(p_profile_list_item);
                            *p_errinfo = GTA_ERROR_MEMORY;
                            goto err;
                        }
                    }
                    else {
                        p_inst_obj->params.os_functions.free(p_profile_list_item);
                        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
                        goto err;
                    }
                }
                else {
                    *p_errinfo = GTA_ERROR_MEMORY;
                    goto err;
                }
            }
            else {
                /*
                 * Profile already exists: Priorities not yet implemented, so we
                 * fail here.
                 */
                *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
                goto err;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            goto err;
        }
    }

err:
    return b_ret;
}

static struct instance_provider_object_t *
check_instance_provider_handle(
    gta_instance_handle_t h_inst,
    gta_errinfo_t * p_errinfo);

static object_t *
create_instance_provider_object(
    instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo);

static bool
destroy_instance_provider_object(
    struct instance_provider_object_t * p_instance_provider_obj,
    gta_errinfo_t * p_errinfo);

GTA_DEFINE_FUNCTION(void *, gta_provider_get_params,
(
    gta_instance_handle_t h_inst,
    gta_errinfo_t * p_errinfo
))
{
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    void * p_provider_params = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return NULL;
    }

    /* this function is always called from a provider, i.e. the instance
       handle is expected to be wrapped into instance_provider */
    p_instance_provider_obj = check_instance_provider_handle(h_inst, p_errinfo);
    if (NULL != p_instance_provider_obj)
    {
        p_provider_params = p_instance_provider_obj->p_provider->p_provider_params;
    }

    return p_provider_params;
}


GTA_DECLARE_FUNCTION(gta_mutex_t, no_mutex_create, ());
GTA_DECLARE_FUNCTION(bool, no_mutex_destroy, (gta_mutex_t mutex));
GTA_DECLARE_FUNCTION(bool, no_mutex_lock, (gta_mutex_t mutex));
GTA_DECLARE_FUNCTION(bool, no_mutex_unlock, (gta_mutex_t mutex));

GTA_DEFINE_FUNCTION(gta_instance_handle_t, gta_instance_init,
(
    const struct gta_instance_params_t * p_instance_params,
    gta_errinfo_t * p_errinfo
))
{
    gta_instance_handle_t h_inst = GTA_HANDLE_INVALID;
    instance_object_t * p_inst_obj = NULL_PTR;
    struct gta_instance_params_t instance_params = { 0 };
    struct access_policy_object_t * p_access_policy_obj_simple_initial = NULL;
    struct access_policy_object_t * p_access_policy_obj_simple_basic = NULL;
    struct access_policy_object_t * p_access_policy_obj_simple_physical_presence = NULL;
    struct access_token_descriptor_object_list_item_t * p_physical_presence_access_token_descriptor = NULL;

    //access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL_PTR;
    gta_access_descriptor_handle_t h_token_descriptor = GTA_HANDLE_INVALID;

    if (true != basic_pointer_validation(p_errinfo, p_instance_params)) {
        return GTA_HANDLE_INVALID;
    }

    /* get local read/write copy of params */
    memcpy(&instance_params, p_instance_params, sizeof(struct gta_instance_params_t));

    /* sanity checks for syncronization functions */
    if (NULL != instance_params.global_mutex) {
        /* all four syncronization functions need to be provided */
        if ((NULL == instance_params.os_functions.mutex_create)
        || (NULL == instance_params.os_functions.mutex_destroy)
        || (NULL == instance_params.os_functions.mutex_lock)
        || (NULL == instance_params.os_functions.mutex_unlock)) {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            goto err;
        }
    }
    else
    {
        /* redirect to dummy syncronization functions */
        instance_params.os_functions.mutex_create = no_mutex_create;
        instance_params.os_functions.mutex_lock = no_mutex_lock;
        instance_params.os_functions.mutex_unlock = no_mutex_unlock;
        instance_params.os_functions.mutex_destroy = no_mutex_destroy;
        instance_params.global_mutex = no_mutex_create();
    }

#if THREADS
    if (instance_params.os_functions.mutex_lock(instance_params.global_mutex)) {
#endif

        init_g_handle_map();

        /* check parameters */
#ifdef _CRTDBG_MAP_ALLOC
        if (   (NULL == instance_params.os_functions._calloc_dbg)
            || (NULL == instance_params.os_functions._free_dbg))
#else
        if (   (NULL == instance_params.os_functions.calloc)
            || (NULL == instance_params.os_functions.free))
#endif
        {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            goto err;
        }

        h_inst = alloc_handle(GTA_HANDLE_TYPE_INSTANCE, &instance_params,
            (void **)(&p_inst_obj), p_errinfo);
        if (!h_inst) goto err;

        /*
            * reserve static handles for simple access policies
            *
            * \todo This could also be done (more efficiently) using completely
            *       static data objects and using a set of reserved handle values.
            *       This would requires some dedicated logic inside the handle
            *       management which is currently avoided by using dynamically
            *       allocated handles.
            */

        /* initial */
        p_inst_obj->h_access_policy_simple_initial = alloc_handle(
                GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE,
                p_inst_obj, (void **)(&p_access_policy_obj_simple_initial), p_errinfo);
        if (!p_inst_obj->h_access_policy_simple_initial) goto err;

        h_token_descriptor = alloc_handle(GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_access_policy_obj_simple_initial,
            (void **)(&(p_access_policy_obj_simple_initial->p_initial_access_token_descriptor)), p_errinfo);
        if (GTA_HANDLE_INVALID == h_token_descriptor) goto err;
        p_access_policy_obj_simple_initial->p_initial_access_token_descriptor->type
            = GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL;
        p_access_policy_obj_simple_initial->p_initial_access_token_descriptor->h_self
            = h_token_descriptor;

        list_append_front((struct list_t **)(&(p_access_policy_obj_simple_initial->p_access_token_descriptor_list)),
            p_access_policy_obj_simple_initial->p_initial_access_token_descriptor);

        /* basic */
        p_inst_obj->h_access_policy_simple_basic = alloc_handle(
            GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE, p_inst_obj,
            (void **)(&p_access_policy_obj_simple_basic), p_errinfo);
        if (!p_inst_obj->h_access_policy_simple_basic) goto err;

        h_token_descriptor = alloc_handle(GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_access_policy_obj_simple_basic,
            (void **)(&(p_access_policy_obj_simple_basic->p_basic_access_token_descriptor)), p_errinfo);
        if (GTA_HANDLE_INVALID == h_token_descriptor) goto err;
        p_access_policy_obj_simple_basic->p_basic_access_token_descriptor->type
            = GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN;
        p_access_policy_obj_simple_basic->p_basic_access_token_descriptor->h_self
            = h_token_descriptor;

        list_append_front((struct list_t **)(&(p_access_policy_obj_simple_basic->p_access_token_descriptor_list)),
            p_access_policy_obj_simple_basic->p_basic_access_token_descriptor);

        /* physical presence */
        p_inst_obj->h_access_policy_simple_physical_presence = alloc_handle(
            GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE, p_inst_obj,
            (void **)(&p_access_policy_obj_simple_physical_presence), p_errinfo);
        if (!p_inst_obj->h_access_policy_simple_physical_presence) goto err;

        h_token_descriptor = alloc_handle(GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_access_policy_obj_simple_physical_presence,
            (void **)&p_physical_presence_access_token_descriptor, p_errinfo);
        if (GTA_HANDLE_INVALID == h_token_descriptor) goto err;
        p_physical_presence_access_token_descriptor->type
            = GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN;
        p_physical_presence_access_token_descriptor->h_self
            = h_token_descriptor;

        list_append_front((struct list_t **)(&(p_access_policy_obj_simple_physical_presence->p_access_token_descriptor_list)),
            p_physical_presence_access_token_descriptor);

#if THREADS
    }
    else
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
    }
#endif

    return h_inst;

err:
    {
        gta_errinfo_t errinfo;
        gta_instance_final(h_inst, &errinfo);
    }

    return GTA_HANDLE_INVALID;
}


GTA_DEFINE_FUNCTION(bool, gta_instance_final,
(
    gta_instance_handle_t h_inst,
    gta_errinfo_t * p_errinfo
))
{
    instance_object_t * p_inst_obj = NULL_PTR;
    struct provider_list_item_t * p_provider_list_item;
    struct provider_list_item_t * p_provider_list_item_next;
    struct profile_list_item_t * p_profile_list_item;
    struct profile_list_item_t * p_profile_list_item_next;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);
    if (NULL != p_inst_obj) {
        p_provider_list_item = p_inst_obj->p_provider_list;
        while (NULL != p_provider_list_item) {
            p_provider_list_item->pf_free_params(
                p_provider_list_item->p_provider_params);
            free_handle(p_provider_list_item->h_ctx, p_errinfo);
            p_provider_list_item_next = p_provider_list_item->p_next;
            p_inst_obj->params.os_functions.free(p_provider_list_item);
            p_provider_list_item = p_provider_list_item_next;
        }
        p_profile_list_item = p_inst_obj->p_profile_list;
        while (NULL != p_profile_list_item) {
            p_inst_obj->params.os_functions.free(
                p_profile_list_item->profile_name);
            p_profile_list_item_next = p_profile_list_item->p_next;
            p_inst_obj->params.os_functions.free(p_profile_list_item);
            p_profile_list_item = p_profile_list_item_next;
        }
        return free_handle(h_inst, p_errinfo);
    }

    return false;
}

static struct provider_list_item_t *
find_personality(gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    gta_errinfo_t * p_errinfo);

GTA_DEFINE_FUNCTION(gta_context_handle_t, gta_context_open,
(
    gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    const gta_profile_name_t profile,
    gta_errinfo_t * p_errinfo
))
{
    instance_object_t * p_inst_obj = NULL;
    gta_context_handle_t h_prectx = GTA_HANDLE_INVALID; /* preliminary context */
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    context_object_t * p_ctx_obj = NULL_PTR;

    struct provider_list_item_t * p_provider_list_item;
    struct profile_list_item_t * p_profile_list_item;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL != p_inst_obj) {
        /* Check personality_name and profile */
        if ((NULL != personality_name) && (NULL != profile)) {
            /* Find provider holding the personality in question */
            p_provider_list_item = find_personality(h_inst, personality_name,
                &errinfo);
            if (NULL != p_provider_list_item) {
                /* Check whether the profile in question is supported by
                 * provider */
                p_profile_list_item = list_find(
                    (struct list_t *)(p_inst_obj->p_profile_list),
                    profile, profile_name_cmp);
                if ((NULL != p_profile_list_item) && (p_provider_list_item == p_profile_list_item->p_provider)) {
                    h_prectx = alloc_handle(GTA_HANDLE_TYPE_CONTEXT, p_inst_obj,
                        (void **)(&p_ctx_obj), p_errinfo);
                    p_ctx_obj->p_provider = p_provider_list_item;
                    if (NULL != p_provider_list_item->function_list->pf_gta_provider_context_open) {
                        if (p_provider_list_item->function_list->pf_gta_provider_context_open(h_prectx,
                            personality_name, profile, &(p_ctx_obj->p_context_params), p_errinfo)) {
                            h_ctx = h_prectx;
                        }
                        else {
                            /* tear down preliminary context */
                            gta_errinfo_t err;
                            /* error returned fromfree_handle must not hide
                             * error returned by context_open .*/
                            free_handle(h_prectx, &err);
                        }
                    }
                    else {
                        *p_errinfo = GTA_ERROR_PROVIDER_INVALID;
                    }
                }
                else {
                    *p_errinfo = GTA_ERROR_PROFILE_UNSUPPORTED;
                }
            }
            else {
                /* todo(thomas.zeschg): error code? */
                *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        }
    }
    return h_ctx;
}


GTA_DEFINE_FUNCTION(bool, gta_context_close,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (p_ctx_obj)
    {
        /* notify provider on close_context */
        if (NULL != p_ctx_obj->p_provider->function_list->pf_gta_provider_context_close) {
            p_ctx_obj->p_provider->function_list->pf_gta_provider_context_close(h_ctx, p_errinfo);
        }

        /* free memory allocated using gta_secmem_calloc()
           within the scope of this context */
        while (p_ctx_obj->p_secmem_first) {
            gta_secmem_free(h_ctx, p_ctx_obj->p_secmem_first->ptr, p_errinfo);
        }
    }

    return free_handle(h_ctx, p_errinfo);
}


GTA_DEFINE_FUNCTION(bool, gta_access_token_get_physical_presence,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t physical_presence_token,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    instance_object_t * p_inst_obj = NULL;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    if (true != basic_pointer_validation(p_errinfo, physical_presence_token)) {
        return false;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo))) {
        /* TODO: Currently it is not clear how to select the matching provider
         * or whether forward the request to all registered providers. This
         * "hack" assumes that only one provider is registered and therefore
         * simply the first provider in the list is selected.
         */
        p_provider_list_item = p_inst_obj->p_provider_list;
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider_list_item;
        }

        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider_list_item,
            gta_access_token_get_physical_presence, (h_inst_provider,
                physical_presence_token, p_errinfo));
        free_handle(h_inst_provider, &errinfo_tmp);
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }
    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_access_token_get_issuing,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t granting_token,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    instance_object_t * p_inst_obj = NULL;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    if (true != basic_pointer_validation(p_errinfo, granting_token)) {
        return false;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo))) {
        /* TODO: Currently it is not clear how to select the matching provider
         * or whether forward the request to all registered providers. This
         * "hack" assumes that only one provider is registered and therefore
         * simply the first provider in the list is selected.
         */
        p_provider_list_item = p_inst_obj->p_provider_list;
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider_list_item;
        }

        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider_list_item,
            gta_access_token_get_issuing, (h_inst_provider,
                granting_token, p_errinfo));
        free_handle(h_inst_provider, &errinfo_tmp);
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }
    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_access_token_get_basic,
(
    gta_instance_handle_t h_inst,
    const gta_access_token_t granting_token,
    const gta_personality_name_t personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t basic_access_token,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    instance_object_t * p_inst_obj = NULL;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    if (true != basic_pointer_validation(p_errinfo, granting_token, personality_name, basic_access_token)) {
        return false;
    }

    /* Range check on usage. Only "use" and "admin" are allowed here. */
    if (usage > GTA_ACCESS_TOKEN_USAGE_ADMIN) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo))) {
        /* TODO: Currently it is not clear how to select the matching provider
         * or whether forward the request to all registered providers. This
         * "hack" assumes that only one provider is registered and therefore
         * simply the first provider in the list is selected.
         */
        p_provider_list_item = p_inst_obj->p_provider_list;
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider_list_item;
        }

        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider_list_item,
            gta_access_token_get_basic, (h_inst_provider,
                granting_token, personality_name, usage, basic_access_token,
                p_errinfo));
        free_handle(h_inst_provider, &errinfo_tmp);
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }
    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_access_token_get_pers_derived,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t target_personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t * p_pers_derived_access_token,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, target_personality_name, p_pers_derived_access_token)) {
        return false;
    }

    /* Range check on usage */
    if (usage > GTA_ACCESS_TOKEN_USAGE_RECEDE) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_access_token_get_pers_derived, (h_ctx,
                target_personality_name, usage, p_pers_derived_access_token,
                p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_access_token_revoke,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token_tbr,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    instance_object_t * p_inst_obj = NULL;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    gta_errinfo_t errinfo_tmp = GTA_ERROR_INTERNAL_ERROR;

    if (true != basic_pointer_validation(p_errinfo, access_token_tbr)) {
        return false;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo))) {
        /* TODO: Currently it is not clear how to select the matching provider
         * or whether forward the request to all registered providers. This
         * "hack" assumes that only one provider is registered and therefore
         * simply the first provider in the list is selected.
         */
        p_provider_list_item = p_inst_obj->p_provider_list;
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider_list_item;
        }

        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider_list_item,
            gta_access_token_revoke, (h_inst_provider, access_token_tbr, p_errinfo));
        free_handle(h_inst_provider, &errinfo_tmp);
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }
    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_context_auth_set_access_token,
(
    gta_context_handle_t h_ctx,
    const gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, access_token)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_context_auth_set_access_token, (h_ctx, access_token,
                p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_context_auth_get_challenge,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * challenge,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, challenge)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_context_auth_get_challenge, (h_ctx, challenge, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_context_auth_set_random,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * random,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, random)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_context_auth_set_random, (h_ctx, random, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_context_set_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrtype, p_attrvalue)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        /* todo Is there something to to do before forwarding function to
         * provider? */
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_context_set_attribute, (h_ctx, attrtype, p_attrvalue,
                p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(void *, gta_context_get_provider_params,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;
    void * p_provider_params = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return NULL;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (p_ctx_obj)
    {
        p_provider_params = p_ctx_obj->p_provider->p_provider_params;
    }
    return p_provider_params;
}


GTA_DEFINE_FUNCTION(void *, gta_context_get_params,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;
    void * p_context_params = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return NULL;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (p_ctx_obj)
    {
        p_context_params = p_ctx_obj->p_context_params;
    }

    return p_context_params;
}


/*
 * Access policy handling
 */

GTA_DEFINE_FUNCTION(gta_access_policy_handle_t, gta_access_policy_simple,
(
    gta_instance_handle_t h_inst,
    gta_access_descriptor_type_t access_token_descriptor_type,
    gta_errinfo_t * p_errinfo
    ))
{
    instance_object_t * p_inst_obj = NULL;
    gta_access_policy_handle_t h_access_policy = GTA_HANDLE_INVALID;

    if (true != basic_pointer_validation(p_errinfo)) {
        return GTA_HANDLE_INVALID;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo)))
    {
        switch (access_token_descriptor_type) {
        case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
            h_access_policy = p_inst_obj->h_access_policy_simple_initial;
            break;
        case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
            h_access_policy = p_inst_obj->h_access_policy_simple_basic;
            break;
        case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
            h_access_policy = p_inst_obj->h_access_policy_simple_physical_presence;
            break;
        default:
            *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
            break;
        }
    }

    return h_access_policy;
}


GTA_DEFINE_FUNCTION(gta_access_policy_handle_t, gta_access_policy_create,
(
    gta_instance_handle_t h_inst,
    gta_errinfo_t * p_errinfo
    ))
{
    instance_object_t * p_inst_obj = NULL;
    gta_access_policy_handle_t h_access_policy = GTA_HANDLE_INVALID;
    struct access_policy_object_t * p_access_policy_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return GTA_HANDLE_INVALID;
    }

    if ((p_inst_obj = check_instance_handle(h_inst, p_errinfo)))
    {
        h_access_policy = alloc_handle(GTA_HANDLE_TYPE_ACCESS_POLICY, p_inst_obj,
            (void **)(&p_access_policy_obj), p_errinfo);
    }

    return h_access_policy;
}


GTA_DEFINE_FUNCTION(bool, gta_access_policy_destroy,
(
    gta_access_policy_handle_t h_access_policy,
    gta_errinfo_t * p_errinfo
    ))
{
    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    /* Explicit check is required since it is not allowed to call
       gta_access_policy_destroy() with GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE */
    if (check_access_policy_handle(h_access_policy, false, p_errinfo)) {
        return free_handle(h_access_policy, p_errinfo);
    }

    return false;
}



GTA_DEFINE_FUNCTION(bool, gta_access_policy_add_basic_access_token_descriptor,
(
    gta_access_policy_handle_t h_access_policy,
    gta_errinfo_t * p_errinfo
    ))
{
    struct access_policy_object_t * p_access_policy_obj = NULL_PTR;
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL_PTR;
    gta_access_descriptor_handle_t h_token_descriptor = GTA_HANDLE_INVALID;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    p_access_policy_obj = (/* const_cast */struct access_policy_object_t *)
        check_access_policy_handle(h_access_policy, false, p_errinfo);
    if (p_access_policy_obj)
    {
        /* basic access policy descriptor is a singleton */
        if (p_access_policy_obj->p_basic_access_token_descriptor == NULL) {

            /* Allocate access token descriptor.
               This is done via alloc_handle() as gta_access_policy_enumerate()
               is supposed to return handles.
               The access token descriptor itself does not contain any private/sensible information. */
            h_token_descriptor = alloc_handle(GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_access_policy_obj,
                (void **)(&p_token_descriptor_object), p_errinfo);
            if (GTA_HANDLE_INVALID == h_token_descriptor) goto err;

            p_token_descriptor_object->h_self = h_token_descriptor;
            p_token_descriptor_object->type = GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN;
            p_access_policy_obj->p_basic_access_token_descriptor = p_token_descriptor_object;
            list_append_front((struct list_t **)(&(p_access_policy_obj->p_access_token_descriptor_list)),
                p_token_descriptor_object);
        }
    }
    else {
        return false;
    }

    return true;

    /* error handling */
err:
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_access_policy_add_pers_derived_access_token_descriptor,
(
    gta_access_policy_handle_t h_access_policy,
    const gta_personality_fingerprint_t personality_fingerprint,
    const gta_profile_name_t verification_profile_name,
    gta_errinfo_t * p_errinfo
    ))
{
    struct access_policy_object_t * p_access_policy_obj = NULL_PTR;
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL_PTR;
    gta_access_descriptor_handle_t h_token_descriptor = GTA_HANDLE_INVALID;
    gta_profile_name_t verification_profile_name_copy = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, personality_fingerprint, verification_profile_name)) {
        return false;
    }

    p_access_policy_obj = (/* const cast */ struct access_policy_object_t *)
        check_access_policy_handle(h_access_policy, false, p_errinfo);
    if (p_access_policy_obj)
    {
        verification_profile_name_copy
            = p_access_policy_obj->p_inst_obj->params.os_functions.calloc(1, strlen(verification_profile_name) + 1);
        if (NULL_PTR == verification_profile_name_copy) {
            *p_errinfo = GTA_ERROR_MEMORY;
            goto err;
        }

        /* Allocate access token descriptor.
           This is done via alloc_handle() as gta_access_policy_enumerate()
           is supposed to return handles.
           The access token descriptor itself does not contain any private/sensible information. */
        h_token_descriptor = alloc_handle(GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_access_policy_obj,
            (void **)(&p_token_descriptor_object), p_errinfo);
        if (GTA_HANDLE_INVALID == h_token_descriptor) goto err;

        p_token_descriptor_object->h_self = h_token_descriptor;
        p_token_descriptor_object->type = GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN;
        p_token_descriptor_object->pers_derived.profile_name = verification_profile_name_copy;
        memcpy(p_token_descriptor_object->pers_derived.profile_name,
            verification_profile_name, strlen(verification_profile_name));
        memcpy(p_token_descriptor_object->pers_derived.pers_fingerprint,
            personality_fingerprint, sizeof(gta_personality_fingerprint_t));

        list_append_front((struct list_t **)(&(p_access_policy_obj->p_access_token_descriptor_list)),
            p_token_descriptor_object);
    }
    else {
        return false;
    }

    return true;

    /* error handling */
err:
    if (verification_profile_name_copy) {
        p_access_policy_obj->p_inst_obj->params.os_functions.free(
            verification_profile_name_copy);
    }

    return false;
}


/*
 * Secure memory management
 */

GTA_DEFINE_FUNCTION(void *, gta_secmem_calloc,
(
    gta_context_handle_t h_ctx, size_t n, size_t size,
    gta_errinfo_t * p_errinfo
))
{
    calloc_t p_calloc = NULL;
    context_object_t * p_ctx_obj = NULL;
    struct secmem_block_t * p_secmem = NULL;
    void * ptr = NULL;

    if (true != basic_pointer_validation(p_errinfo)) {
        return NULL;
    }

    if ((p_ctx_obj = check_context_handle(h_ctx, p_errinfo)))
    {
#ifdef _CRTDBG_MAP_ALLOC
        p_calloc = p_ctx_obj->p_inst_obj->params.os_functions._calloc_dbg;
        p_secmem = p_calloc(1, sizeof(struct secmem_block_t),
            _NORMAL_BLOCK, __FILE__, __LINE__);
#else
        p_calloc = p_ctx_obj->p_inst_obj->params.os_functions.calloc;
        p_secmem = p_calloc(1, sizeof(struct secmem_block_t));
#endif
        if (p_secmem) {
#ifdef _CRTDBG_MAP_ALLOC
            ptr = p_calloc(n, size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
            ptr = p_calloc(n, size);
#endif
            if (ptr) {
                p_secmem->n = n;
                p_secmem->size = size;
                p_secmem->ptr = ptr;
#if THREADS == 1
#endif /* THREADS */
                /* do bookkeeping for secmem blocks list */
                list_append_front((struct list_t **)&(p_ctx_obj->p_secmem_first), p_secmem);
#if THREADS == 1
#endif /* THREADS */
            }
            else
            {
                p_ctx_obj->p_inst_obj->params.os_functions.free(p_secmem);
                *p_errinfo = GTA_ERROR_MEMORY;
            }
        }
        else
        {
            *p_errinfo = GTA_ERROR_MEMORY;
        }
    }

    return ptr;
}


static bool
secmem_block_cmp(void * p_block1, void * p_block2);

GTA_DEFINE_FUNCTION(bool, gta_secmem_free,
(
    gta_context_handle_t h_ctx, void * ptr,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    context_object_t * p_ctx_obj = NULL;
    struct secmem_block_t block = { 0 };
    struct secmem_block_t * p_secmem_block = NULL;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    if ((p_ctx_obj = check_context_handle(h_ctx, p_errinfo)))
    {
        block.ptr = ptr;
        p_secmem_block = list_remove((struct list_t **)&(p_ctx_obj->p_secmem_first),
                                     &block, (list_item_cmp)secmem_block_cmp);
        if (p_secmem_block)
        {
            gta_memset(p_secmem_block->ptr, p_secmem_block->n * p_secmem_block->size,
                    0, p_secmem_block->n * p_secmem_block->size);
            p_ctx_obj->p_inst_obj->params.os_functions.free(p_secmem_block->ptr);
            gta_memset(p_secmem_block, sizeof(struct secmem_block_t), 0,
                    sizeof(struct secmem_block_t));
            p_ctx_obj->p_inst_obj->params.os_functions.free(p_secmem_block);
            b_ret = true;
        }
        else
        {
            *p_errinfo = GTA_ERROR_PTR_INVALID;
        }
    }

    return b_ret;
}


GTA_DEFINE_FUNCTION(void *, gta_secmem_checkptr,
(
    gta_context_handle_t h_ctx, void * p_check,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL;
    struct secmem_block_t block = {0};
    block.p_next = p_check;

    if (true != basic_pointer_validation(p_errinfo, p_check)) {
        return NULL;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (p_ctx_obj)
    {
        if (list_find((struct list_t *)(p_ctx_obj->p_secmem_first),
                      &block, (list_item_cmp)secmem_block_cmp))
        {
            return p_check;
        }
    }

    return NULL;
}


/*
 * Syncronization
 */

GTA_DEFINE_FUNCTION(gta_mutex_t, gta_mutex_create,
(
    gta_context_handle_t h_ctx
))
{
    gta_errinfo_t errinfo; /* @todo: Pass through parameter list? */
    context_object_t * p_ctx_obj = NULL;
    gta_mutex_t p_mutex = NULL;

    p_ctx_obj = check_context_handle(h_ctx, &errinfo);
    if (p_ctx_obj)
    {
        p_mutex = p_ctx_obj->p_inst_obj->params.os_functions.mutex_create();
    }

    return p_mutex;
}


GTA_DEFINE_FUNCTION(bool, gta_mutex_destroy,
(
    gta_context_handle_t h_ctx,
    gta_mutex_t mutex
))
{
    gta_errinfo_t errinfo; /* @todo: Pass through parameter list? */
    context_object_t * p_ctx_obj = NULL;

    p_ctx_obj = check_context_handle(h_ctx, &errinfo);
    if (p_ctx_obj) {
        return p_ctx_obj->p_inst_obj->params.os_functions.mutex_destroy(mutex);
    }

    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_mutex_lock,
(
    gta_context_handle_t h_ctx,
    gta_mutex_t mutex
))
{
    gta_errinfo_t errinfo; /* @todo: Pass through parameter list? */
    context_object_t * p_ctx_obj = NULL;

    p_ctx_obj = check_context_handle(h_ctx, &errinfo);
    if (p_ctx_obj)
    {
        return p_ctx_obj->p_inst_obj->params.os_functions.mutex_lock(mutex);
    }

    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_mutex_unlock,
(
    gta_context_handle_t h_ctx,
    gta_mutex_t mutex
))
{
    gta_errinfo_t errinfo; /* @todo: Pass through parameter list? */
    context_object_t * p_ctx_obj = NULL;

    p_ctx_obj = check_context_handle(h_ctx, &errinfo);
    if (p_ctx_obj)
    {
        return p_ctx_obj->p_inst_obj->params.os_functions.mutex_unlock(mutex);
    }

    return false;
}

/* Stream function to compare a stream output with a string */
typedef struct ocmpstream {
    /* public interface as defined for gtaio_ostream */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* private implementation details */
    char * buf; /* buffer holding the string to compare with the stream output */
    size_t pos; /* current position in the buffer */
    enum {
        CMP_ONGOING,
        CMP_EQUAL,
        CMP_UNEQUAL
    } cmp_result;
} ocmpstream_t;

static size_t ocmpstream_write
(
    ocmpstream_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    if (CMP_ONGOING == ostream->cmp_result) {
        /* Check whether the current part of the string matches */
        if (0 == strncmp(data, (ostream->buf + ostream->pos), len)) {
            /* Check whether the end of both strings is reached */
            if (('\0' == data[len - 1]) && ('\0' == ostream->buf[ostream->pos + len - 1])) {
                ostream->cmp_result = CMP_EQUAL;
            }
            else {
                ostream->pos += len;
            }
        }
        else {
            ostream->cmp_result = CMP_UNEQUAL;
        }
    }
    return len;
}

static size_t ostream_null_write(
    gtaio_ostream_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
    )
{
    return len;
}

static bool ostream_finish
(
    gtaio_stream_finish_t * ostream,
    gta_errinfo_t errinfo,
    gta_errinfo_t * p_errinfo
)
{
    return true;
}

static void ocmpstream_init (ocmpstream_t * ostream, char * buf)
{
    ostream->write = (gtaio_stream_write_t)ocmpstream_write;
    ostream->finish = (gtaio_stream_finish_t)ostream_finish;
    ostream->buf = buf;
    ostream->pos = 0;
    ostream->cmp_result = CMP_ONGOING;
}

GTA_DEFINE_FUNCTION(bool, gta_identifier_assign,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_type_t identifier_type,
    const gta_identifier_value_t identifier_value,
    gta_errinfo_t * p_errinfo
))
{
    bool b_ret = false;
    bool b_loop = true;
    bool b_name_clash = false;
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;

    instance_object_t * p_inst_obj = NULL_PTR;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;

    gtaio_ostream_t o_idtype = { 0 };
    o_idtype.write = (gtaio_stream_write_t)ostream_null_write;
    o_idtype.finish = (gtaio_stream_finish_t)ostream_finish;
    ocmpstream_t o_idvalue = { 0 };

    if (true != basic_pointer_validation(p_errinfo, identifier_type, identifier_value)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL != p_inst_obj) {
        /* wrap h_inst */
        p_provider_list_item = p_inst_obj->p_provider_list;
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider_list_item;
            /*
             * Check for potential name clashes needs to be done on the
             * framework level as each provider only has a partial view.
             * todo: this highly depends on how identifier a managed with
             * multiple providers -> future work
             */
            while (b_loop) {
                ocmpstream_init(&o_idvalue, identifier_value);
                if (gta_identifier_enumerate(h_inst, &h_enum, &o_idtype,
                        (gtaio_ostream_t *)&o_idvalue, &errinfo)) {

                    if (CMP_EQUAL == o_idvalue.cmp_result) {
                        /* Name clash found */
                        b_name_clash = true;
                        /* The enumeration could end here, but for cleaning up
                         * the enum handle it is required to enumerate until the
                         * end */
                    }
                }
                else {
                    if (GTA_ERROR_ENUM_NO_MORE_ITEMS != errinfo) {
                        /* Error in enumeration */
                        *p_errinfo = errinfo;
                        b_loop = false;
                    }
                    else {
                        /* Enumeration finished successfully */
                        b_loop = false;

                        if (b_name_clash) {
                            *p_errinfo = GTA_ERROR_NAME_ALREADY_EXISTS;
                        }
                        else {
                            /* @todo(thomas.zeschg): decide to which provider
                             * the identifier should be assigned */
                            b_ret = GTA_PROVIDER_FWD_FUNCTION(
                                p_provider_list_item, gta_identifier_assign,
                                (h_inst_provider, identifier_type,
                                identifier_value, p_errinfo));
                        }
                    }
                }
            }
            free_handle(h_inst_provider, p_errinfo);
        }
    }

    return b_ret;
}

static struct framework_enum_object_t *
get_framework_enum_obj(
    instance_object_t * p_inst_obj,
    gta_enum_handle_t * ph_enum
    )
{
    struct framework_enum_object_t * p_framework_enum_obj = NULL_PTR;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* Check whether or not a new enum handle needs to be allocated */
    if (GTA_HANDLE_ENUM_FIRST == *ph_enum) {
        *ph_enum = alloc_handle(GTA_HANDLE_TYPE_FRAMEWORK_ENUM,
            p_inst_obj, (void **)(&p_framework_enum_obj), &errinfo);
        if (NULL != p_framework_enum_obj) {
            p_framework_enum_obj->h_enum = GTA_HANDLE_ENUM_FIRST;
            p_framework_enum_obj->p_provider = p_inst_obj->p_provider_list;
        }
    }
    else {
        p_framework_enum_obj = check_framework_enum_handle(*ph_enum,
            &errinfo);
    }
    return p_framework_enum_obj;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_enumerate,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
))
{
    instance_object_t * p_inst_obj = NULL_PTR;
    struct framework_enum_object_t * p_framework_enum_obj = NULL_PTR;
    bool b_ret = false;
    bool b_loop = true;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_errinfo_t tmp_errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, identifier_value, ph_enum, personality_name)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL == p_inst_obj) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    /* Check if the provider list is empty */
    if (NULL == p_inst_obj->p_provider_list) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    /* Check whether flags parameter is one of the supported ones */
    if ((GTA_PERSONALITY_ENUM_ALL != flags)
        && (GTA_PERSONALITY_ENUM_ACTIVE != flags)
        && (GTA_PERSONALITY_ENUM_INACTIVE != flags)) {

        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    p_framework_enum_obj = get_framework_enum_obj(p_inst_obj, ph_enum);

    /* Check if we have a valid handle */
    if ((NULL == p_framework_enum_obj) ||
        (p_inst_obj != p_framework_enum_obj->p_inst_obj)) {

        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
        p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
    if (GTA_HANDLE_INVALID == h_inst_provider) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    p_instance_provider_obj->h_inst = h_inst;
    while(b_loop) {
        /*
         * This is a naive approach, assuming that different providers can have
         * the same identifier somehow.
         * We should only forward the enumerate function to providers holding
         * the provided identifier.
         */
        p_instance_provider_obj->p_provider = p_framework_enum_obj->p_provider;

        /* Forward gta_personality_enumerate to provider */
        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_framework_enum_obj->p_provider,
            gta_personality_enumerate, (h_inst_provider, identifier_value,
            &(p_framework_enum_obj->h_enum), flags, personality_name,
            &errinfo));

        if (b_ret) {
            /* current enumeration operation was successful, nothing to do */
            b_loop = false;
        }
        else {
            if (GTA_ERROR_ENUM_NO_MORE_ITEMS == errinfo) {
                /*
                 * No more items in current provider, check if there are more
                 * provider in the list
                 */
                if (NULL != p_framework_enum_obj->p_provider->p_next) {
                    p_framework_enum_obj->p_provider = p_framework_enum_obj->p_provider->p_next;
                    p_framework_enum_obj->h_enum = GTA_HANDLE_ENUM_FIRST;
                }
                else {
                    /* Enumeration finished */
                    *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
                    b_loop = false;
                    free_handle(*ph_enum, &errinfo);
                }
            }
            else {
                /* An error occurred */
                *p_errinfo = errinfo;
                b_loop = false;
                free_handle(*ph_enum, &errinfo);
            }
        }
    }
    free_handle(h_inst_provider, &tmp_errinfo);
    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_enumerate_application,
(
    gta_instance_handle_t h_inst,
    const gta_application_name_t application_name,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
))
{
    instance_object_t * p_inst_obj = NULL_PTR;
    struct framework_enum_object_t * p_framework_enum_obj = NULL_PTR;
    bool b_ret = false;
    bool b_loop = true;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_errinfo_t tmp_errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, application_name, ph_enum, personality_name)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL == p_inst_obj) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    /* Check if the provider list is empty */
    if (NULL == p_inst_obj->p_provider_list) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    /* Check whether flags parameter is one of the supported ones */
    if ((GTA_PERSONALITY_ENUM_ALL != flags)
        && (GTA_PERSONALITY_ENUM_ACTIVE != flags)
        && (GTA_PERSONALITY_ENUM_INACTIVE != flags)) {

        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    p_framework_enum_obj = get_framework_enum_obj(p_inst_obj, ph_enum);

    /* Check if we have a valid handle */
    if ((NULL == p_framework_enum_obj) ||
        (p_inst_obj != p_framework_enum_obj->p_inst_obj)) {

        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
        p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
    if (GTA_HANDLE_INVALID == h_inst_provider) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    p_instance_provider_obj->h_inst = h_inst;
    while(b_loop) {
        /*
         * This is a naive approach, assuming that different providers can have
         * the same identifier somehow.
         * We should only forward the enumerate function to providers holding
         * the provided identifier.
         */
        p_instance_provider_obj->p_provider = p_framework_enum_obj->p_provider;

        /* Forward gta_personality_enumerate to provider */
        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_framework_enum_obj->p_provider,
            gta_personality_enumerate_application, (h_inst_provider, application_name,
            &(p_framework_enum_obj->h_enum), flags, personality_name,
            &errinfo));

        if (b_ret) {
            /* current enumeration operation was successful, nothing to do */
            b_loop = false;
        }
        else {
            if (GTA_ERROR_ENUM_NO_MORE_ITEMS == errinfo) {
                /*
                 * No more items in current provider, check if there are more
                 * provider in the list
                 */
                if (NULL != p_framework_enum_obj->p_provider->p_next) {
                    p_framework_enum_obj->p_provider = p_framework_enum_obj->p_provider->p_next;
                    p_framework_enum_obj->h_enum = GTA_HANDLE_ENUM_FIRST;
                }
                else {
                    /* Enumeration finished */
                    *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
                    b_loop = false;
                    free_handle(*ph_enum, &errinfo);
                }
            }
            else {
                /* An error occurred */
                *p_errinfo = errinfo;
                b_loop = false;
                free_handle(*ph_enum, &errinfo);
            }
        }
    }
    free_handle(h_inst_provider, &tmp_errinfo);
    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_identifier_enumerate,
(
    gta_instance_handle_t h_inst,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * identifier_type,
    gtaio_ostream_t * identifier_value,
    gta_errinfo_t * p_errinfo
    ))
{
    instance_object_t * p_inst_obj = NULL_PTR;
    struct framework_enum_object_t * p_framework_enum_obj = NULL_PTR;
    bool b_ret = false;
    bool b_loop = true;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_errinfo_t tmp_errinfo = GTA_ERROR_INTERNAL_ERROR;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, ph_enum, identifier_type, identifier_value)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL == p_inst_obj) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    /* Check if the provider list is empty */
    if (NULL == p_inst_obj->p_provider_list) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    p_framework_enum_obj = get_framework_enum_obj(p_inst_obj, ph_enum);

    /* Check if we have a valid handle */
    if ((NULL == p_framework_enum_obj) ||
        (p_inst_obj != p_framework_enum_obj->p_inst_obj)) {

        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
        p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
    if (GTA_HANDLE_INVALID == h_inst_provider) {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
    p_instance_provider_obj->h_inst = h_inst;
    /*
     * todo: this highly depends on how identifier a managed with multiple
     * providers. It could be that there are duplicates... -> future work
     */
    while(b_loop) {
        p_instance_provider_obj->p_provider = p_framework_enum_obj->p_provider;

        /* Forward gta_identifier_enumerate to provider */
        b_ret = GTA_PROVIDER_FWD_FUNCTION(p_framework_enum_obj->p_provider,
            gta_identifier_enumerate, (h_inst_provider,
                &(p_framework_enum_obj->h_enum), identifier_type,
                identifier_value, &errinfo));

        if (b_ret) {
            /* current enumeration operation was successful, nothing to do */
            b_loop = false;
        }
        else {
            if (GTA_ERROR_ENUM_NO_MORE_ITEMS == errinfo) {
                /*
                 * No more items in current provider, check if there are more
                 * provider in the list
                 */
                if (NULL != p_framework_enum_obj->p_provider->p_next) {
                    p_framework_enum_obj->p_provider = p_framework_enum_obj->p_provider->p_next;
                    p_framework_enum_obj->h_enum = GTA_HANDLE_ENUM_FIRST;
                }
                else {
                    /* Enumeration finished */
                    *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
                    b_loop = false;
                    free_handle(*ph_enum, &errinfo);
                }
            }
            else {
                /* An error occurred */
                *p_errinfo = errinfo;
                b_loop = false;
                free_handle(*ph_enum, &errinfo);
            }
        }
    }
    free_handle(h_inst_provider, &tmp_errinfo);
    return b_ret;
}

/*
 * GTA API functions indirecting to a provider.
 */

static struct provider_list_item_t *
select_provider_by_profile(gta_instance_handle_t h_inst,
    const gta_profile_name_t profile, gta_errinfo_t * p_errinfo)
{
    instance_object_t * p_inst_obj;
    struct provider_list_item_t * p_provider_list_item = NULL_PTR;
    struct profile_list_item_t * p_profile_list_item = NULL_PTR;

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL != p_inst_obj) {
        p_profile_list_item = list_find(
            (struct list_t *)(p_inst_obj->p_profile_list),
            profile, profile_name_cmp);
        if (NULL != p_profile_list_item) {
            p_provider_list_item = p_profile_list_item->p_provider;
        }
    }

    return p_provider_list_item;
}

/* Auxiliary function for gta_personality_create and gta_personality_deploy */
static bool
personality_deploy_create(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gtaio_istream_t * personality_content,
    gta_access_policy_handle_t auth_use,
    gta_access_policy_handle_t auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    )
{
    bool b_ret = false;
    struct provider_list_item_t * p_provider = NULL;
    gta_instance_handle_t h_inst_provider = GTA_HANDLE_INVALID;
    instance_object_t * p_inst_obj = NULL_PTR;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    /* Check handle */
    if (NULL != p_inst_obj) {
        /* Check auth handles */
        if ((NULL != check_access_policy_handle(auth_admin, true, p_errinfo))
            && (NULL != check_access_policy_handle(auth_use, true, p_errinfo))) {

            /* Check for potential name clashes */
            if (NULL == find_personality(h_inst, personality_name, p_errinfo)) {
                p_provider = select_provider_by_profile(h_inst, profile, p_errinfo);
            }
            else {
                *p_errinfo = GTA_ERROR_NAME_ALREADY_EXISTS;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_ACCESS_POLICY;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }

    if (NULL != p_provider) {
        h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
            p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
        if (GTA_HANDLE_INVALID != h_inst_provider) {
            p_instance_provider_obj->h_inst = h_inst;
            p_instance_provider_obj->p_provider = p_provider;
            /* Decide whether to call gta_personality_deploy or
             * gta_personality_create */
            if (NULL != personality_content) {
                b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider,
                    gta_personality_deploy, (h_inst_provider, identifier_value,
                    personality_name, application, profile, personality_content,
                    auth_use, auth_admin, requested_protection_properties,
                    p_errinfo));
            }
            else {
                b_ret = GTA_PROVIDER_FWD_FUNCTION(p_provider,
                    gta_personality_create, (h_inst_provider, identifier_value,
                    personality_name, application, profile, auth_use,
                    auth_admin, requested_protection_properties, p_errinfo));
            }
            free_handle(h_inst_provider, p_errinfo);
        }
    }
    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_deploy,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gtaio_istream_t * personality_content,
    gta_access_policy_handle_t auth_use,
    gta_access_policy_handle_t auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    bool b_ret = false;

    if (true == basic_pointer_validation(p_errinfo, identifier_value, personality_name, application, profile, personality_content)) {
        b_ret = personality_deploy_create(h_inst, identifier_value,
            personality_name, application, profile, personality_content,
            auth_use, auth_admin, requested_protection_properties, p_errinfo);
    }

    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_personality_create,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gta_access_policy_handle_t auth_use,
    gta_access_policy_handle_t auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    bool b_ret = false;

    if (true == basic_pointer_validation(p_errinfo, identifier_value, personality_name, application, profile)) {
        b_ret = personality_deploy_create(h_inst, identifier_value,
            personality_name, application, profile, NULL, auth_use, auth_admin,
            requested_protection_properties, p_errinfo);
    }

    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, gta_personality_enroll, (
            gta_context_handle_t h_ctx,
            gtaio_ostream_t * p_personality_enrollment_info,
            gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, p_personality_enrollment_info)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_enroll, (h_ctx, p_personality_enrollment_info,
                p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_personality_add_trusted_attribute, (
        gta_context_handle_t h_ctx,
        const gta_personality_attribute_type_t attrtype,
        const gta_personality_attribute_name_t attrname,
        gtaio_istream_t * p_attrvalue,
        gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrtype, attrname, p_attrvalue)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_add_trusted_attribute, (h_ctx, attrtype, attrname,
                p_attrvalue, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_personality_add_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrtype, attrname, p_attrvalue)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_add_attribute, (h_ctx, attrtype, attrname,
                p_attrvalue, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_personality_get_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrname, p_attrvalue)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
           gta_personality_get_attribute, (h_ctx, attrname, p_attrvalue,
            p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_remove_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrname)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_remove_attribute, (h_ctx, attrname, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_deactivate_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrname)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_deactivate_attribute, (h_ctx, attrname, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_activate_attribute, (
    gta_context_handle_t h_ctx,
    gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, attrname)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_personality_activate_attribute, (h_ctx, attrname, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_personality_attributes_enumerate, (
    gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * attribute_type,
    gtaio_ostream_t * attribute_name,
    gta_errinfo_t * p_errinfo
))
{
    instance_object_t * p_inst_obj = NULL;
    struct instance_provider_object_t * p_instance_provider_obj = NULL_PTR;
    gta_instance_handle_t h_inst_provider = NULL;
    struct provider_list_item_t * p_provider_list_item;
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    bool ret = false;

    if (true != basic_pointer_validation(p_errinfo, personality_name, ph_enum, attribute_type, attribute_name)) {
        return false;
    }

    p_inst_obj = check_instance_handle(h_inst, p_errinfo);

    if (NULL != p_inst_obj) {
        /* Find provider holding the personality in question */
        p_provider_list_item = find_personality(h_inst, personality_name,
            &errinfo);
        if (NULL != p_provider_list_item) {
            h_inst_provider = alloc_handle(GTA_HANDLE_TYPE_INSTANCE_PROVIDER,
                p_inst_obj, (void **)(&p_instance_provider_obj), p_errinfo);
            if (GTA_HANDLE_INVALID != h_inst_provider) {
                p_instance_provider_obj->h_inst = h_inst;
                p_instance_provider_obj->p_provider = p_provider_list_item;
                ret = GTA_PROVIDER_FWD_FUNCTION(p_provider_list_item,
                    gta_personality_attributes_enumerate, (h_inst_provider,
                        personality_name, ph_enum, attribute_type,
                        attribute_name, p_errinfo));
                free_handle(h_inst_provider, &errinfo);
            }
            else {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_ITEM_NOT_FOUND;
        }
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }
    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_seal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * protected_data,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, data, protected_data)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_seal_data, (h_ctx, data, protected_data, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_unseal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * protected_data,
    gtaio_ostream_t * data,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, protected_data, data)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
            gta_unseal_data, (h_ctx, protected_data, data, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}


GTA_DEFINE_FUNCTION(bool, gta_verify, (
    gta_context_handle_t h_ctx,
    gtaio_istream_t * claim,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, claim)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (NULL != p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
           gta_verify, (h_ctx, claim, p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

GTA_DEFINE_FUNCTION(bool, gta_authenticate_data_detached, (
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
))
{
    context_object_t * p_ctx_obj = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo, data, seal)) {
        return false;
    }

    p_ctx_obj = check_context_handle(h_ctx, p_errinfo);
    if (p_ctx_obj) {
        return GTA_PROVIDER_FWD_FUNCTION(p_ctx_obj->p_provider,
           gta_authenticate_data_detached, (h_ctx, data, seal,
           p_errinfo));
    }
    *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    return false;
}

/*
 * Static module local functions
 */

/* factory function for all kinds of objects managed via handles */
static gta_handle_t
alloc_handle(gta_handle_type_t type, void *params,
             void **pp_obj, gta_errinfo_t * p_errinfo)
{
    gta_handle_t handle = GTA_HANDLE_INVALID;
    void *p_obj = NULL_PTR;

    if ((NULL_PTR != pp_obj) && (NULL_PTR != params)) {

#if THREADS
        return_code = my_setlock(GTA_LOCK_HANDLES);
        if (return_code != CES_RETURN_OK)
        {
            return return_code;
        }
#endif

        size_t get = 0;
        get = g_handle_map.get;
        g_handle_map.get = (g_handle_map.get % GTA_HANDLE_MAP_SIZE) + 1;

        if (g_handle_map.get != g_handle_map.release) {
            switch (type) {
            case GTA_HANDLE_TYPE_INSTANCE:
                p_obj = create_instance_object(
                    (struct gta_instance_params_t *)params, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_INSTANCE_PROVIDER:
                p_obj = create_instance_provider_object(
                    (instance_object_t *)params, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_CONTEXT:
                p_obj = create_context_object((instance_object_t *)params,
                    p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_POLICY:
                p_obj = create_access_policy_object((instance_object_t *)params,
                    p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE:
                p_obj = create_access_policy_object((instance_object_t *)params,
                    p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR:
                p_obj = create_access_token_descriptor_object(
                    (struct access_policy_object_t *)params, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_FRAMEWORK_ENUM:
                p_obj = create_framework_enum_object(
                    (instance_object_t *)params, p_errinfo);
                break;
            default:
                break;
            }

            if (NULL_PTR != p_obj) {
                handle = (void *)g_handle_map.free[get];
                g_handle_map.free[get] = 0;
                g_handle_map.map[(size_t)handle].type = type;
                g_handle_map.map[(size_t)handle].p = p_obj;
                *pp_obj = p_obj;
            } else {
                /* Recover initial g_handle_map.get value */
                g_handle_map.get = get;
                /* Use p_errinfo from subfunctions */
                handle = GTA_HANDLE_INVALID;
            }
        } else {
            /* Recover initial g_handle_map.get value */
            g_handle_map.get = get;
            *p_errinfo = GTA_ERROR_HANDLES_EXAUSTED;
            handle = GTA_HANDLE_INVALID;
        }

#if THREADS
        my_unlock(GTA_LOCK_HANDLES);
#endif
    }
    return handle;
}


static bool
free_handle(gta_handle_t handle, gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;

    /* basic sanity checks */
    if ((handle != GTA_HANDLE_INVALID)
        && ((size_t)handle <= GTA_HANDLE_MAP_SIZE)) {

#if THREADS
        return_code = my_setlock(GTA_LOCK_HANDLES);
        if (return_code != CES_RETURN_OK)
        {
            return return_code;
        }
#endif

        if (g_handle_map.map[(size_t)handle].p != NULL_PTR)
        {
            /* release resources associated with the handle */
            switch (g_handle_map.map[(size_t)handle].type) {
            case GTA_HANDLE_TYPE_INSTANCE:
                b_ret = destroy_instance_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_INSTANCE_PROVIDER:
                b_ret = destroy_instance_provider_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_CONTEXT:
                b_ret = destroy_context_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_POLICY:
                b_ret = destroy_access_policy_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE:
                b_ret = destroy_access_policy_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR:
                b_ret = destroy_access_token_descriptor_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            case GTA_HANDLE_TYPE_FRAMEWORK_ENUM:
                b_ret = destroy_framework_enum_object(
                    g_handle_map.map[(size_t)handle].p, p_errinfo);
                break;
            default:
                break;
            }

            if (b_ret) {
                gta_memset(&(g_handle_map.map[(size_t)handle]),
                        sizeof(handle_map_entry_t), 0, sizeof(handle_map_entry_t));
                g_handle_map.free[g_handle_map.release] = handle;

                g_handle_map.release = (g_handle_map.release %
                    GTA_HANDLE_MAP_SIZE) + 1;
            }
            else {
                *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            }
        }
        else {
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        }

#if THREADS
        my_unlock(GTA_LOCK_HANDLES);
#endif
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }

    return b_ret;
}


static void *
check_handle(gta_handle_t handle, gta_handle_type_t type, gta_errinfo_t * p_errinfo)
{
    /* pointer to the object referred to by handle */
    object_t * p_obj = NULL_PTR;
    /* basic sanity checks */
    if ((handle != GTA_HANDLE_INVALID)
        && ((size_t)handle <= GTA_HANDLE_MAP_SIZE)) {

#if 0
        return_code = my_setlock(GTA_LOCK_HANDLES);
        if (return_code != CES_RETURN_OK)
        {
            return return_code;
        }
#endif

        if ((g_handle_map.map[(size_t)handle].type == type)
            && (g_handle_map.map[(size_t)handle].p != NULL_PTR))
        {
            p_obj = g_handle_map.map[(size_t)handle].p;
        }
        else {
            *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        }

#if 0
        my_unlock(GTA_LOCK_HANDLES);
#endif
    }
    else {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
    }

    return p_obj;
}


static object_t *
create_instance_object(const struct gta_instance_params_t * p_params, gta_errinfo_t * p_errinfo)
{
    instance_object_t * p_inst_obj = NULL;

    if (p_params != NULL) {
        p_inst_obj = p_params->os_functions.calloc(1, sizeof(instance_object_t));
        if (NULL == p_inst_obj) {
            *p_errinfo = GTA_ERROR_MEMORY;
        }
        else { /* initialize object */
            memcpy((/* const cast */ struct gta_instance_params_t *)(&(p_inst_obj->params)),
                p_params, sizeof(struct gta_instance_params_t));
        }
    }

    return (object_t *)p_inst_obj;
}


static bool
destroy_instance_object(instance_object_t * p_inst_obj, gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;
    gta_errinfo_t errinfo = 0;

    if (p_inst_obj != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_inst_obj->params.os_functions._free_dbg;
#else
        p_free = p_inst_obj->params.os_functions.free; /* save ptr value before
                                                          erasing the object */
#endif

        /* @todo tear down providers */

        /* release handles to static simple access policies - errors are ignored on purpose */
        free_handle(p_inst_obj->h_access_policy_simple_initial, &errinfo);
        free_handle(p_inst_obj->h_access_policy_simple_basic, &errinfo);
        free_handle(p_inst_obj->h_access_policy_simple_physical_presence, &errinfo);

        gta_memset(p_inst_obj, sizeof(instance_object_t), 0, sizeof(instance_object_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_inst_obj, _NORMAL_BLOCK);
#else
        p_free(p_inst_obj);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}



static struct instance_provider_object_t *
check_instance_provider_handle(gta_instance_handle_t h_inst,
    gta_errinfo_t * p_errinfo)
{
    return (struct instance_provider_object_t *)check_handle(h_inst,
        GTA_HANDLE_TYPE_INSTANCE_PROVIDER, p_errinfo);
}

static object_t *
create_instance_provider_object(instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo)
{
    struct instance_provider_object_t * p_instance_provider_obj = NULL;
    p_instance_provider_obj = p_inst_obj->params.os_functions.calloc(1,
        sizeof(struct instance_provider_object_t));
    if (NULL == p_instance_provider_obj) {
        *p_errinfo = GTA_ERROR_MEMORY;
    }
    else { /* initialize object */
        p_instance_provider_obj->p_inst_obj = p_inst_obj;
    }
    return (object_t *)p_instance_provider_obj;
}

static bool
destroy_instance_provider_object(
    struct instance_provider_object_t * p_instance_provider_obj,
    gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;

    if (NULL != p_instance_provider_obj) {
        /* save ptr value before erasing the object */
        p_free = p_instance_provider_obj->p_inst_obj->params.os_functions.free;

        gta_memset(p_instance_provider_obj, sizeof(struct instance_provider_object_t),
                0, sizeof(struct instance_provider_object_t));
        p_free(p_instance_provider_obj);
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}

/* return pointer to instance structure identified by handle */
static instance_object_t *
check_instance_handle(gta_instance_handle_t h_inst, gta_errinfo_t * p_errinfo)
{
#if 0 /* @todo need to check whether check_instance_handle() should also
               resolved wrapped instance_provider handles */
    gta_errinfo_t errinfo = 0;
    struct instance_provider_object_t * p_instance_provider_object = NULL_PTR;

    p_instance_provider_object
        = check_instance_provider_handle(gta_instance_handle_t h_inst,
            &errinfo);
    if (p_instance_provider_object) h_inst = p_instance_provider_object->h_inst;
#endif

    return (instance_object_t *)check_handle(h_inst, GTA_HANDLE_TYPE_INSTANCE, p_errinfo);
}


static object_t *
create_context_object(instance_object_t * p_inst_obj, gta_errinfo_t * p_errinfo)
{
    context_object_t * p_ctx_obj = NULL;

    p_ctx_obj = p_inst_obj->params.os_functions.calloc(1, sizeof(context_object_t));
    if (NULL == p_ctx_obj) {
        *p_errinfo = GTA_ERROR_MEMORY;
    }
    else { /* initialize object */
        p_ctx_obj->p_inst_obj = p_inst_obj;
    }

    return (object_t *)p_ctx_obj;
}


static bool
destroy_context_object(context_object_t * p_ctx_obj, gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;
    struct secmem_block_t * p_secmem_block = NULL;

    if (p_ctx_obj != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_ctx_obj->p_inst_obj->params.os_functions._free_dbg;
#else
        p_free = p_ctx_obj->p_inst_obj->params.os_functions.free; /* save ptr value before
                                                                     erasing the object */
#endif
        while (NULL != (p_secmem_block = list_remove_front((struct list_t **)(&(p_ctx_obj->p_secmem_first)))))
        {
            /* code below is redundant to gta_secmem_free()
               but avoids having to know the context handle */
            gta_memset(p_secmem_block->ptr, p_secmem_block->n * p_secmem_block->size,
                    0, p_secmem_block->n * p_secmem_block->size);
            p_ctx_obj->p_inst_obj->params.os_functions.free(p_secmem_block->ptr);
            gta_memset(p_secmem_block, sizeof(struct secmem_block_t),
                    0, sizeof(struct secmem_block_t));
            p_ctx_obj->p_inst_obj->params.os_functions.free(p_secmem_block);
        }

        gta_memset(p_ctx_obj, sizeof(context_object_t),
                0, sizeof(context_object_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_ctx_obj, _NORMAL_BLOCK);
#else
        p_free(p_ctx_obj);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}



/* return pointer to context structure identified by handle */
static context_object_t *
check_context_handle(gta_context_handle_t h_ctx, gta_errinfo_t * p_errinfo)
{
    return (context_object_t *)check_handle(h_ctx, GTA_HANDLE_TYPE_CONTEXT, p_errinfo);
}


static object_t *
create_access_policy_object(instance_object_t * p_inst_obj, gta_errinfo_t * p_errinfo)
{
    struct access_policy_object_t * p_access_policy_obj = NULL;

    p_access_policy_obj = p_inst_obj->params.os_functions.calloc(1, sizeof(struct access_policy_object_t));
    if (NULL == p_access_policy_obj) {
        *p_errinfo = GTA_ERROR_MEMORY;
    }
    else { /* initialize object */
        p_access_policy_obj->p_inst_obj = p_inst_obj;
    }

    return (object_t *)p_access_policy_obj;
}

/* todo(thomas.zeschg): remove this? */
#define GTA_HANDLE_ENUM_FINISHED ((gta_context_handle_t)-2)


static struct framework_enum_object_t *
check_framework_enum_handle(gta_enum_handle_t h_enum, gta_errinfo_t * p_errinfo)
{
    return (struct framework_enum_object_t *)check_handle(h_enum,
        GTA_HANDLE_TYPE_FRAMEWORK_ENUM, p_errinfo);
}

static object_t *
create_framework_enum_object(instance_object_t * p_inst_obj,
    gta_errinfo_t * p_errinfo)
{
    struct framework_enum_object_t * p_framework_enum_obj = NULL;
    p_framework_enum_obj = p_inst_obj->params.os_functions.calloc(1,
        sizeof(struct framework_enum_object_t));
    if (NULL == p_framework_enum_obj) {
        *p_errinfo = GTA_ERROR_MEMORY;
    }
    else { /* initialize object */
        p_framework_enum_obj->p_inst_obj = p_inst_obj;
    }

    return (object_t *)p_framework_enum_obj;
}

static bool
destroy_framework_enum_object(
    struct framework_enum_object_t * p_framework_enum_obj,
    gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;

    if (p_framework_enum_obj != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_framework_enum_obj->p_inst_obj->params.os_functions._free_dbg;
#else
        /* save ptr value before erasing the object */
        p_free = p_framework_enum_obj->p_inst_obj->params.os_functions.free;
#endif
        gta_memset(p_framework_enum_obj, sizeof(struct framework_enum_object_t),
                0, sizeof(struct framework_enum_object_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_framework_enum_obj, _NORMAL_BLOCK);
#else
        p_free(p_framework_enum_obj);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}

GTA_DEFINE_FUNCTION(bool, gta_access_policy_enumerate,
(
    gta_access_policy_handle_t h_access_policy,
    gta_enum_handle_t * ph_enum,
    gta_access_descriptor_handle_t * ph_access_token_descriptor,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    const struct access_policy_object_t * p_access_policy_obj = NULL_PTR;
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL_PTR;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    /* check parameters */
    p_access_policy_obj = check_access_policy_handle(h_access_policy, true, p_errinfo);
    if (NULL == p_access_policy_obj) return false;
    if (   NULL == ph_enum
        || NULL == ph_access_token_descriptor)
    {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }
    if (*ph_enum == GTA_HANDLE_INVALID) {
        *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        return false;
    }

    if (*ph_enum == GTA_HANDLE_ENUM_FINISHED) {
         *ph_enum = GTA_HANDLE_INVALID;
         *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
         return false;
    }

    if ((*ph_enum == GTA_HANDLE_ENUM_FIRST) &&
       (NULL == (gta_enum_handle_t)p_access_policy_obj->p_access_token_descriptor_list)) {
        /* Note: this handles an edge case where the list is empty */
        *ph_enum = GTA_HANDLE_INVALID;
        *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
        return false;
    }

    if (*ph_enum == GTA_HANDLE_ENUM_FIRST) {
        *ph_enum = (gta_enum_handle_t)p_access_policy_obj->p_access_token_descriptor_list->h_self;
    }

    p_token_descriptor_object = check_access_token_descriptor_handle(*ph_enum, p_errinfo);
    if (p_token_descriptor_object)
    {
        *ph_access_token_descriptor = p_token_descriptor_object->h_self;

        p_token_descriptor_object = p_token_descriptor_object->p_next;
        if (p_token_descriptor_object) {
            *ph_enum = p_token_descriptor_object->h_self;
        }
        else {
            *ph_enum = GTA_HANDLE_ENUM_FINISHED;
        }

        ret = true;
    }

    return ret;
}


GTA_DEFINE_FUNCTION(bool, gta_access_policy_get_access_descriptor_type,
(
    gta_access_policy_handle_t h_access_policy,
    gta_access_descriptor_handle_t h_access_token_descriptor,
    gta_access_descriptor_type_t * p_access_token_descriptor_type,
    gta_errinfo_t * p_errinfo
    ))
{
    const struct access_policy_object_t * p_access_policy_obj = NULL_PTR;
    const struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    /* check parameters */
    p_access_policy_obj = check_access_policy_handle(h_access_policy, true, p_errinfo);
    if (NULL == p_access_policy_obj) return false;
    if (NULL == p_access_token_descriptor_type) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }
    p_token_descriptor_object = check_access_token_descriptor_handle(
        h_access_token_descriptor,
        p_errinfo);
    if (NULL == p_token_descriptor_object) return false;

    *p_access_token_descriptor_type = p_token_descriptor_object->type;

    return true;
}


GTA_DEFINE_FUNCTION(bool, gta_access_policy_get_access_descriptor_attribute,
(
    gta_access_descriptor_handle_t h_access_token_descriptor,
    gta_access_descriptor_attribute_type_t attr_type,
    const char ** pp_attr,
    size_t * p_attr_len,
    gta_errinfo_t * p_errinfo
    ))
{
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL;

    if (true != basic_pointer_validation(p_errinfo)) {
        return false;
    }

    /* check parameters */
    p_token_descriptor_object = check_access_token_descriptor_handle(
        h_access_token_descriptor,
        p_errinfo);
    if (NULL == p_token_descriptor_object) return false;
    if (   NULL == pp_attr
        || NULL == p_attr_len) {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
        return false;
    }

    switch (p_token_descriptor_object->type) {
    /* tokens without any attributes */
    case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
    case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
    case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
        *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
        return false;

    case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
        switch (attr_type) {
        case GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME:
            *pp_attr = p_token_descriptor_object->pers_derived.profile_name;
            *p_attr_len = strlen(p_token_descriptor_object->pers_derived.profile_name);
            break;
        case GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT:
            *pp_attr = p_token_descriptor_object->pers_derived.pers_fingerprint;
            *p_attr_len = sizeof(gta_personality_fingerprint_t);
            break;
        default:
            *p_errinfo = GTA_ERROR_INVALID_ATTRIBUTE;
            return false;
        }
        break;
    default:
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }

    return true;
}


static bool
destroy_access_policy_object(struct access_policy_object_t * p_access_policy_obj, gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;
    struct access_token_descriptor_object_list_item_t * p_access_token_descriptor_obj = NULL_PTR;

    if (p_access_policy_obj != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_access_policy_obj->p_inst_obj->params.os_functions._free_dbg;
#else
        p_free = p_access_policy_obj->p_inst_obj->params.os_functions.free; /* save ptr value before
                                                                               erasing the object */
#endif

        while (NULL != (p_access_token_descriptor_obj
            = list_remove_front((struct list_t **)(&(p_access_policy_obj->p_access_token_descriptor_list))))) {
            free_handle(p_access_token_descriptor_obj->h_self, p_errinfo);
        }

        gta_memset(p_access_policy_obj, sizeof(struct access_policy_object_t),
                0, sizeof(struct access_policy_object_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_access_policy_obj, _NORMAL_BLOCK);
#else
        p_free(p_access_policy_obj);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}


#if 0
static bool
destroy_access_policy_object_simple(access_policy_object_t * p_access_policy_obj, gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;
    access_token_descriptor_object_list_item_t * p_access_token_descriptor_obj = NULL_PTR;

    if (p_access_policy_obj != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_access_policy_obj->p_inst_obj->params.os_functions._free_dbg;
#else
        p_free = p_access_policy_obj->p_inst_obj->params.os_functions.free; /* save ptr value before
                                                                               erasing the object */
#endif
        gta_memset(p_access_policy_obj, sizeof(access_policy_object_t),
                0, sizeof(access_policy_object_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_access_policy_obj, _NORMAL_BLOCK);
#else
        p_free(p_access_policy_obj);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

    return b_ret;
}
#endif


static const struct access_policy_object_t *
check_access_policy_handle(gta_context_handle_t h_access_policy, bool simple, gta_errinfo_t * p_errinfo)
{
    struct access_policy_object_t * p_access_policy_obj = NULL;

    p_access_policy_obj = (struct access_policy_object_t *)check_handle(h_access_policy, GTA_HANDLE_TYPE_ACCESS_POLICY, p_errinfo);

    /* check whether simple access policies are permitted within the callers context */
    if (   NULL == p_access_policy_obj
        && simple)
    {
        p_access_policy_obj = (struct access_policy_object_t *)check_handle(h_access_policy, GTA_HANDLE_TYPE_ACCESS_POLICY_SIMPLE, p_errinfo);
    }

    return p_access_policy_obj;
}


static object_t *
create_access_token_descriptor_object(struct access_policy_object_t * p_access_policy, gta_errinfo_t * p_errinfo)
{
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object = NULL_PTR;

    p_token_descriptor_object = p_access_policy->p_inst_obj
        ->params.os_functions.calloc(1, sizeof(struct access_token_descriptor_object_list_item_t));
    if (NULL == p_token_descriptor_object) {
        *p_errinfo = GTA_ERROR_MEMORY;
    }
    else { /* initialize object */
        p_token_descriptor_object->p_access_policy_obj = p_access_policy;
    }

    return (object_t *)p_token_descriptor_object;
}


static bool
destroy_access_token_descriptor_object(
    struct access_token_descriptor_object_list_item_t * p_token_descriptor_object,
    gta_errinfo_t * p_errinfo)
{
    bool b_ret = false;
    free_t p_free = NULL;

    if (p_token_descriptor_object != NULL) {
#ifdef _CRTDBG_MAP_ALLOC
        p_free = p_token_descriptor_object->p_access_policy_obj->p_inst_obj
            ->params.os_functions._free_dbg;
#else
        p_free = p_token_descriptor_object->p_access_policy_obj->p_inst_obj
            ->params.os_functions.free; /* save ptr value before erasing the object */
#endif

        switch (p_token_descriptor_object->type) {
        case GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL:
        case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
        case GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN:
            break;
        case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
            /* profile_name is not sensitive, i.e. no memset */
#ifdef _CRTDBG_MAP_ALLOC
            p_free(p_token_descriptor_object->pers_derived.profile_name, _NORMAL_BLOCK);
#else
            p_free(p_token_descriptor_object->pers_derived.profile_name);
#endif
            break;
        default:
            *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
            goto err;
        }

        gta_memset(p_token_descriptor_object,
                sizeof(struct access_token_descriptor_object_list_item_t),
                0, sizeof(struct access_token_descriptor_object_list_item_t));
#ifdef _CRTDBG_MAP_ALLOC
        p_free(p_token_descriptor_object, _NORMAL_BLOCK);
#else
        p_free(p_token_descriptor_object);
#endif
        b_ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_PTR_INVALID;
    }

err:

    return b_ret;
}



/*
 * Dummy syncronization functions
 * These functions are used in case no multithreading is required.
 * Defined using GTA_DEFINE_FUNCTION to get function attributes
 * consistent with the external function pointers
 * (e.g., call conventions).
 */
GTA_DEFINE_FUNCTION(gta_mutex_t, no_mutex_create, ())
{
    return GTA_NO_MUTEX_PTR;
}

GTA_DEFINE_FUNCTION(bool, no_mutex_destroy,
(
    gta_mutex_t mutex
))
{
    if (GTA_NO_MUTEX_PTR == mutex) {
        return true;
    }
    return false;
}

GTA_DEFINE_FUNCTION(bool, no_mutex_lock,
(
    gta_mutex_t mutex
))
{
    if (GTA_NO_MUTEX_PTR == mutex) {
        return true;
    }
    return false;
}

GTA_DEFINE_FUNCTION(bool, no_mutex_unlock,
(
    gta_mutex_t mutex
))
{
    if (GTA_NO_MUTEX_PTR == mutex) {
        return true;
    }
    return false;
}

/* Function used with list_find() to verify whether a specific
   access token descriptor handle is valid, i.e., the referenced
   object is contained in the list maintained inside the policy
   object. */
#if 0
static bool
access_token_descriptor_handle_cmp(gta_access_descriptor_type_t * p_access_token_descriptor,
    gta_access_descriptor_handle_t * p_handle)
{
    if (p_handle) {
        return ((gta_access_descriptor_type_t *)*p_handle == p_access_token_descriptor);
    }
    return false;
}
#endif

static struct access_token_descriptor_object_list_item_t *
check_access_token_descriptor_handle(
    gta_access_descriptor_handle_t h_access_token_descriptor,
    gta_errinfo_t * p_errinfo)
{
#if 1
    return (struct access_token_descriptor_object_list_item_t *)
        check_handle(h_access_token_descriptor, GTA_HANDLE_TYPE_ACCESS_TOKEN_DESCRIPTOR, p_errinfo);
#else
    access_token_descriptor_object_list_item_t * p_object = NULL;

    p_object = list_find(p_access_token_descriptor_list,
        &h_access_token_descriptor, access_token_descriptor_handle_cmp);
    if (p_object == NULL) *p_errinfo = GTA_ERROR_HANDLE_INVALID;

    return p_object;
#endif
}

/*
 * Stream functions for find_personality() to write the output to a temporary
 * buffer.
 */
typedef struct ostream_to_buf {
    /* public interface as defined for gtaio_ostream */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* private implementation details */
    char * buf; /* data buffer */
    size_t buf_size; /* data buffer size */
    size_t buf_pos; /* current position in data buffer */
} ostream_to_buf_t;

static size_t ostream_to_buf_write
(
    ostream_to_buf_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = ostream->buf_size - ostream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as are still available in data buffer */
        len = bytes_available;
    }
    /* Copy the bytes to the buffer */
    memcpy(&(ostream->buf[ostream->buf_pos]), data, len);
    /* Set new position in data buffer */
    ostream->buf_pos += len;

    /* Return number of written bytes */
    return len;
}

static void ostream_to_buf_init
(
    ostream_to_buf_t * ostream,
    char * buf,
    size_t buf_size
)
{
    ostream->write = (gtaio_stream_write_t)ostream_to_buf_write;
    ostream->finish = (gtaio_stream_finish_t)ostream_finish;
    ostream->buf = buf;
    ostream->buf_size = buf_size;
    ostream->buf_pos = 0;
}

/* Auxiliary function to search a personality in the currently registered
 * providers. Returns p_provider_list_item if found, otherwise NULL */
static struct provider_list_item_t *
find_personality(gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    gta_errinfo_t * p_errinfo)
{
    struct framework_enum_object_t * p_framework_enum_obj = NULL_PTR;
    struct provider_list_item_t * p_provider_list_item = NULL;

    gtaio_ostream_t o_idtype = { 0 };
    o_idtype.write = (gtaio_stream_write_t)ostream_null_write;
    o_idtype.finish = (gtaio_stream_finish_t)ostream_finish;
    ostream_to_buf_t o_idvalue = { 0 };
    ocmpstream_t o_persname = { 0 };
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;
    bool b_idloop = true;
    bool b_persloop = true;
    gta_enum_handle_t h_idenum = GTA_HANDLE_ENUM_FIRST;

    /* loop over all identifier */
    while (b_idloop) {
        /* Setup ostream_to_buf for identifier value */
        char idvaluebuf[100] = { 0 };
        ostream_to_buf_init(&o_idvalue, idvaluebuf, sizeof(idvaluebuf));
        if (gta_identifier_enumerate(h_inst, &h_idenum, &o_idtype,
                (gtaio_ostream_t *)&o_idvalue, &errinfo)) {
            /* Enumerate personalities of current identifier */
            b_persloop = true;
            gta_enum_handle_t h_persenum = GTA_HANDLE_ENUM_FIRST;
            while (b_persloop) {
                ocmpstream_init(&o_persname, personality_name);
                if (gta_personality_enumerate(h_inst, idvaluebuf, &h_persenum,
                    GTA_PERSONALITY_ENUM_ALL, (gtaio_ostream_t *)&o_persname,
                    &errinfo)) {
                    if (CMP_EQUAL == o_persname.cmp_result) {
                        /* Personality found. Now we need to figure out the
                         * provider holding the personality */
                        p_framework_enum_obj = check_framework_enum_handle(
                            h_persenum, p_errinfo);
                        if (NULL != p_framework_enum_obj) {
                            p_provider_list_item = p_framework_enum_obj->p_provider;
                        }
                        else {
                            /* todo(thomas.zeschg): how to handle an error
                             * here? */
                        }

                        /* Even if we found the personality, we loop until the
                         * end, so that the enum handles are cleaned up */
                    }
                }
                else {
                    b_persloop = false;
                    if (GTA_ERROR_ENUM_NO_MORE_ITEMS != errinfo) {
                        /* Error in enumeration */
                        *p_errinfo = errinfo;
                    }
                }
            }
        }
        else {
            b_idloop = false;
            if (GTA_ERROR_ENUM_NO_MORE_ITEMS != errinfo) {
                /* Error in enumeration */
                *p_errinfo = errinfo;
            }
        }
    }
    return p_provider_list_item;
}

/*
 * Auxiliary function for secmen list management
 */

static bool
secmem_block_cmp(void * p_block1, void * p_block2)
{
    bool b_ret = false;
    const struct secmem_block_t * p_secmem_block1 =
        (struct secmem_block_t *)(p_block1);
    const struct secmem_block_t * p_secmem_block2 =
        (struct secmem_block_t *)(p_block2);

    if ((NULL_PTR != p_secmem_block1) && (NULL_PTR != p_secmem_block2)
        && (p_secmem_block1->ptr == p_secmem_block2->ptr)) {
        b_ret = true;
    }
    return b_ret;
}

/*
 * Auxiliary function for provider list management
 */

static bool
provider_uid_cmp(void * p_provider_list_item, void * p_uid)
{
    bool b_ret = false;
    const struct provider_list_item_t * p_provider =
        (struct provider_list_item_t *)(p_provider_list_item);

    if ((NULL_PTR != p_provider) && (p_provider->uid == p_uid)) {
        b_ret = true;
    }
    return b_ret;
}

/*
 * Auxiliary function for profile list management
 */

static bool
profile_name_cmp(void * p_profile_list_item, void * p_profile_name)
{
    bool b_ret = false;
    const struct profile_list_item_t * p_profile_list_itm =
        (struct profile_list_item_t *)(p_profile_list_item);

    if ((NULL_PTR != p_profile_list_itm) &&
        (0 == strcmp(p_profile_list_itm->profile_name, p_profile_name))) {

        b_ret = true;
    }
    return b_ret;
}


/*** end of file ***/

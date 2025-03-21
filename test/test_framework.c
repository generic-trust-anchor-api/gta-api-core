/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#ifdef WINDOWS
#include <stdlib.h>
#include <crtdbg.h>
#include <gta_windows.h>
#endif /* WINDOWS */

#ifdef LINUX
#include <gta_linux.h>
#endif /* LINUX */

#include <gta_api.h>
#include <gta_memset.h>

extern const struct gta_function_list_t * unittest_provider_init(gta_context_handle_t, gtaio_istream_t *, gtaio_ostream_t *, void **, void(**)(void *),  gta_errinfo_t *);

struct framework_test_params_t {
    gta_instance_handle_t h_inst;
    gta_context_handle_t h_ctx;
    gta_instance_handle_t h_inst_mutex;
    gta_context_handle_t h_ctx_mutex;
    gta_mutex_t global_mutex;
};

/*-----------------------------------------------------------------------------
 * GTA tests suites
 */

int
init_suite_framework(void **state)
{
    struct framework_test_params_t * framework_test_params = NULL;
    gta_errinfo_t errinfo = 0;
    struct gta_instance_params_t inst_params = { 0 };

    framework_test_params = malloc(sizeof(struct framework_test_params_t));
    assert_non_null(framework_test_params);
    framework_test_params->h_inst = NULL;
    framework_test_params->h_ctx = NULL;
    framework_test_params->h_inst_mutex = NULL;
    framework_test_params->h_ctx_mutex = NULL;
    framework_test_params->global_mutex = NULL;
    *state = framework_test_params;

    /* Instance init */
    framework_test_params->h_inst = gta_instance_init(NULL, &errinfo);
    assert_null(framework_test_params->h_inst);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    framework_test_params->h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.calloc = &calloc;
    framework_test_params->h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.free = &free;

#ifdef LINUX
    framework_test_params->global_mutex = gta_linux_mutex_create();
    assert_non_null(framework_test_params->global_mutex);
    inst_params.global_mutex = framework_test_params->global_mutex;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_create = &gta_linux_mutex_create;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_destroy = &gta_linux_mutex_destroy;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_lock = &gta_linux_mutex_lock;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_unlock = &gta_linux_mutex_unlock;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(framework_test_params->h_inst_mutex);

    inst_params.global_mutex = NULL;
    inst_params.os_functions.mutex_create = NULL;
    inst_params.os_functions.mutex_destroy = NULL;
    inst_params.os_functions.mutex_lock = NULL;
    inst_params.os_functions.mutex_unlock = NULL;
#endif /* LINUX */

#ifdef WINDOWS
    framework_test_params->global_mutex = gta_windows_mutex_create();
    assert_non_null(framework_test_params->global_mutex);
    inst_params.global_mutex = framework_test_params->global_mutex;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_create = &gta_windows_mutex_create;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_destroy = &gta_windows_mutex_destroy;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_lock = &gta_windows_mutex_lock;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_null(framework_test_params->h_inst_mutex);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    inst_params.os_functions.mutex_unlock = &gta_windows_mutex_unlock;
    framework_test_params->h_inst_mutex = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(framework_test_params->h_inst_mutex);

    inst_params.global_mutex = NULL;
    inst_params.os_functions.mutex_create = NULL;
    inst_params.os_functions.mutex_destroy = NULL;
    inst_params.os_functions.mutex_lock = NULL;
    inst_params.os_functions.mutex_unlock = NULL;
#endif /* WINDOWS */

    framework_test_params->h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(framework_test_params->h_inst);

    /* instance_final() negative test */
    assert_false(gta_instance_final(NULL,NULL));

    /* Register provider */
    struct gta_provider_info_t provider_info_wrong = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK + 1 /* unsupported */,
        .provider_init = unittest_provider_init,
        .provider_init_config = NULL,
        .profile_info = {
            .profile_name = NULL,
            .protection_properties = {0},
            .priority = 0
        }
    };
    struct gta_provider_info_t provider_info_1 = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = unittest_provider_init,
        .provider_init_config = NULL,
        .profile_info = {
            .profile_name = "profile1",
            .protection_properties = {0},
            .priority = 0
        }
    };
    struct gta_provider_info_t provider_info_2 = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = unittest_provider_init,
        .provider_init_config = NULL,
        .profile_info = {
            .profile_name = "profile2",
            .protection_properties = {0},
            .priority = 0
        }
    };
    assert_false(gta_register_provider(NULL, &provider_info_wrong, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    assert_false(gta_register_provider(framework_test_params->h_inst, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
    assert_false(gta_register_provider(framework_test_params->h_inst, &provider_info_wrong, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
    provider_info_wrong.type = GTA_PROVIDER_INFO_CALLBACK;
    assert_false(gta_register_provider(framework_test_params->h_inst, &provider_info_wrong, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
    assert_true(gta_register_provider(framework_test_params->h_inst, &provider_info_1, &errinfo));

    /* register same profile with same provider a second time should fail */
    assert_false(gta_register_provider(framework_test_params->h_inst, &provider_info_1, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_register_provider(framework_test_params->h_inst, &provider_info_2, &errinfo));

    /* Context open */
    framework_test_params->h_ctx = gta_context_open(NULL,
        NULL,
        NULL,
        &errinfo);
    assert_null(framework_test_params->h_ctx);
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        "personality1",
        NULL,
        &errinfo);
    assert_null(framework_test_params->h_ctx);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
    framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        NULL,
        "profile1",
        &errinfo);
    assert_null(framework_test_params->h_ctx);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

   framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        "personality4",
        "profile1",
        &errinfo);
    assert_null(framework_test_params->h_ctx);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        "personality1",
        "profile3",
        &errinfo);
    assert_null(framework_test_params->h_ctx);
    assert_int_equal(errinfo, GTA_ERROR_PROFILE_UNSUPPORTED);

    framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        "personality2",
        "profile1",
        &errinfo);
    assert_non_null(framework_test_params->h_ctx);

    if (NULL != framework_test_params->h_inst_mutex) {
        assert_true(gta_register_provider(framework_test_params->h_inst_mutex, &provider_info_1, &errinfo));
        framework_test_params->h_ctx_mutex = gta_context_open(framework_test_params->h_inst_mutex,
            "personality1",
            "profile1",
            &errinfo);
        assert_non_null(framework_test_params->h_ctx_mutex);
    }
    return 0;
}

int
clean_suite_framework(void **state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_false(gta_context_close(NULL, NULL));
    assert_false(gta_context_close(NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    if (NULL != framework_test_params->h_ctx) {
        assert_true(gta_context_close(framework_test_params->h_ctx, &errinfo));
    }
    if (NULL != framework_test_params->h_inst) {
        assert_true(gta_instance_final(framework_test_params->h_inst, &errinfo));
    }

    if (NULL != framework_test_params->h_ctx_mutex) {
        assert_true(gta_context_close(framework_test_params->h_ctx_mutex, &errinfo));
    }

    if (NULL != framework_test_params->h_inst_mutex) {
        assert_true(gta_instance_final(framework_test_params->h_inst_mutex, &errinfo));
    }
#ifdef LINUX
    if (NULL != framework_test_params->global_mutex) {
        assert_true(gta_linux_mutex_destroy(framework_test_params->global_mutex));
        framework_test_params->global_mutex = NULL;
    }
#endif /* LINUX */

#ifdef WINDOWS
    if (NULL != framework_test_params->global_mutex) {
        assert_true(gta_windows_mutex_destroy(framework_test_params->global_mutex));
        framework_test_params->global_mutex = NULL;
    }
#endif /* WINDOWS */

    if (NULL != *state) {
        free(*state);
        *state = NULL;
    }

    return 0;
}

int
init_suite_framework_exceptions(void **state)
{
    struct framework_test_params_t * framework_test_params = NULL;
    gta_errinfo_t errinfo = 0;
    struct gta_instance_params_t inst_params = {
        NULL,
        {
            .calloc = &calloc,
            .free = &free,
            .mutex_create  = NULL,
            .mutex_destroy = NULL,
            .mutex_lock    = NULL,
            .mutex_unlock  = NULL,
        },
        NULL
    };

    framework_test_params = malloc(sizeof(struct framework_test_params_t));
    assert_non_null(framework_test_params);
    framework_test_params->h_inst = NULL;
    framework_test_params->h_ctx = NULL;
    framework_test_params->h_inst_mutex = NULL;
    framework_test_params->h_ctx_mutex = NULL;
    framework_test_params->global_mutex = NULL;
    *state = framework_test_params;

    /* Instance init */
    framework_test_params->h_inst = gta_instance_init(&inst_params, &errinfo);
    assert_non_null(framework_test_params->h_inst);

    return 0;
}

/*
 * framework test suite
 */

/*-----------------------------------------------------------------------------
 * individual test functions
 */

static void
test_gta_access_policy(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    bool ret = false;
    gta_errinfo_t errinfo;
    gta_enum_handle_t h_enum = GTA_HANDLE_INVALID;
    gta_access_descriptor_handle_t h_access_token_descriptor = GTA_HANDLE_INVALID;
    gta_access_descriptor_type_t token_type;
    size_t simple_access_token_descriptor_cnt = 0;
    size_t basic_access_token_descriptor_cnt = 0;
    size_t pers_derived_access_token_descriptor_cnt = 0;

    gta_access_policy_handle_t h_access_policy = GTA_HANDLE_INVALID;
    gta_personality_fingerprint_t personality_fingerprint = {
        (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE,
        (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE,
        (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE,
        (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE, (char)0xAF, (char)0xFE
    };
    gta_profile_name_t profile = "ch.iec.30168.poc_verify";

    /*
     * simple access policies
     */
    gta_access_descriptor_type_t access_token_simple_types[] =
    {
        GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL,
        GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN,
        GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN
    };
    int access_token_simple_types_idx = 0;

    assert_null(gta_access_policy_simple(framework_test_params->h_inst, 0, NULL));

    for (access_token_simple_types_idx = 0;
        (size_t)access_token_simple_types_idx < sizeof(access_token_simple_types) / sizeof(gta_access_descriptor_type_t);
        access_token_simple_types_idx++) {

        gta_access_descriptor_type_t access_token_descriptor_type
            = access_token_simple_types[access_token_simple_types_idx];

        h_access_policy = gta_access_policy_simple(framework_test_params->h_inst, access_token_descriptor_type, &errinfo);
        assert_int_not_equal(GTA_HANDLE_INVALID, h_access_policy);

        /* enumerate the tokens in the access policy */
        simple_access_token_descriptor_cnt = 0;
        h_enum = GTA_HANDLE_ENUM_FIRST;
        do
        {
#if 0
            gta_enum_handle_t h_enum_invalid
                = (gta_enum_handle_t)(((char *)h_enum) + 1);

            /* mess with policy token enumeration handle */
            assert_false(gta_access_policy_enumerate(h_access_policy,
                &h_enum_invalid, &h_access_token_descriptor, &errinfo));
            assert_int_equal(GTA_ERROR_HANDLE_INVALID, errinfo)
#endif

            ret = gta_access_policy_enumerate(h_access_policy,
                &h_enum, &h_access_token_descriptor, &errinfo);

            if (ret)
            {
                const char * p_attr = NULL;
                size_t attr_len = 0;

                assert_false(gta_access_policy_get_access_descriptor_type(h_access_policy,
                    h_access_token_descriptor, &token_type, NULL));
                /* mess with access token descriptor handle */
                assert_false(gta_access_policy_get_access_descriptor_type(h_access_policy,
                    (gta_access_descriptor_handle_t)(((char *)h_access_token_descriptor) + 1),
                    &token_type, &errinfo));
                assert_int_equal(GTA_ERROR_HANDLE_INVALID, errinfo);

                assert_true(gta_access_policy_get_access_descriptor_type(h_access_policy,
                    h_access_token_descriptor, &token_type, &errinfo));

                if (token_type == access_token_descriptor_type) {
                    simple_access_token_descriptor_cnt++;

#if 0 /* this should result in a compile error */
                    p_attr[0] = 1;
#endif
                    assert_false(gta_access_policy_get_access_descriptor_attribute(
                        h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME,
                        &p_attr, &attr_len, NULL));
                    assert_false(gta_access_policy_get_access_descriptor_attribute(
                        h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME,
                        &p_attr, &attr_len, &errinfo));
                    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);

                    assert_false(gta_access_policy_get_access_descriptor_attribute(
                        h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                        &p_attr, &attr_len, &errinfo));
                    assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);
                }
                else {
                    assert_true(false);
                }
            }

        } while (ret);
        assert_int_equal(errinfo, GTA_ERROR_ENUM_NO_MORE_ITEMS);
        assert_int_equal(h_enum, GTA_HANDLE_INVALID);
        assert_int_equal(1, simple_access_token_descriptor_cnt);

        errinfo = 0;
        assert_false(gta_access_policy_destroy(h_access_policy, &errinfo));
        //assert_true(GTA_ERROR_INVALID_PARAMETER == errinfo || 0 == errinfo); TODO!
    }

    errinfo = 0;
    h_access_policy = gta_access_policy_simple(framework_test_params->h_inst,
        GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN, &errinfo);
    assert_int_equal(GTA_HANDLE_INVALID, h_access_policy);
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);


    /*
     * complex access policies
     */
    assert_null(gta_access_policy_create(NULL, NULL));
    h_access_policy = gta_access_policy_create(NULL,
        &errinfo);
    assert_int_equal(GTA_HANDLE_INVALID, h_access_policy);
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    h_access_policy = gta_access_policy_create(framework_test_params->h_inst,
        &errinfo);
    assert_int_not_equal(GTA_HANDLE_INVALID, h_access_policy);

    assert_false(gta_access_policy_add_basic_access_token_descriptor(NULL,
        NULL));
    assert_false(gta_access_policy_add_basic_access_token_descriptor(NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_access_policy_add_basic_access_token_descriptor(
        h_access_policy, &errinfo));

    assert_false(gta_access_policy_add_pers_derived_access_token_descriptor(
        NULL, personality_fingerprint, profile, NULL));
    assert_false(gta_access_policy_add_pers_derived_access_token_descriptor(
        h_access_policy, personality_fingerprint, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
    assert_false(gta_access_policy_add_pers_derived_access_token_descriptor(
        NULL, personality_fingerprint, profile, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_access_policy_add_pers_derived_access_token_descriptor(
        h_access_policy, personality_fingerprint, profile, &errinfo));

    /* enumerate the tokens in the access policy */
    h_enum = GTA_HANDLE_ENUM_FIRST;
    do
    {
#if 0
        gta_enum_handle_t h_enum_invalid
            = (gta_enum_handle_t)(((char *)h_enum)+1);

        /* mess with policy token enumeration handle */
        assert_false(gta_access_policy_enumerate(h_access_policy,
            &h_enum_invalid, &h_access_token_descriptor, &errinfo));
        assert_int_equal(GTA_ERROR_HANDLE_INVALID, errinfo)
#endif

        ret = gta_access_policy_enumerate(h_access_policy,
            &h_enum, &h_access_token_descriptor, &errinfo);

        if (ret)
        {
            const char * p_attr = NULL;
            size_t attr_len = 0;

            /* mess with access token descriptor handle */
            assert_false(gta_access_policy_get_access_descriptor_type(h_access_policy,
               (gta_access_descriptor_handle_t)(((char *)h_access_token_descriptor)+0xFA81),
                &token_type, &errinfo));
            assert_int_equal(GTA_ERROR_HANDLE_INVALID, errinfo);

            assert_true(gta_access_policy_get_access_descriptor_type(h_access_policy,
                h_access_token_descriptor, &token_type, &errinfo));

            switch (token_type)
            {
            case GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN:
                basic_access_token_descriptor_cnt++;

#if 0 /* this should result in a compile error */
                p_attr[0] = 1;
#endif
                assert_false(gta_access_policy_get_access_descriptor_attribute(
                    h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME,
                    &p_attr, &attr_len, &errinfo));
                assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);

                assert_false(gta_access_policy_get_access_descriptor_attribute(
                    h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                    &p_attr, &attr_len, &errinfo));
                assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);

                break;
            case GTA_ACCESS_DESCRIPTOR_TYPE_PERS_DERIVED_TOKEN:
                pers_derived_access_token_descriptor_cnt++;

                assert_false(gta_access_policy_get_access_descriptor_attribute(
                    h_access_token_descriptor,
                    /* invalid attribute */
                    GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME
                    + GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                    &p_attr, &attr_len, &errinfo));
                assert_int_equal(GTA_ERROR_INVALID_ATTRIBUTE, errinfo);

                assert_true(gta_access_policy_get_access_descriptor_attribute(
                    h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PROFILE_NAME,
                    &p_attr, &attr_len, &errinfo));
                assert_int_equal(attr_len, strlen(profile));
                assert_int_equal(0, memcmp(p_attr, profile, attr_len));

                assert_true(gta_access_policy_get_access_descriptor_attribute(
                    h_access_token_descriptor, GTA_ACCESS_DESCRIPTOR_ATTR_PERS_FINGERPRINT,
                    &p_attr, &attr_len, &errinfo));
                assert_int_equal(attr_len, sizeof(gta_personality_fingerprint_t));
                assert_int_equal(0, memcmp(p_attr, personality_fingerprint, attr_len));

                break;
            default:
                assert_true(false);
                break;
            }
        }

    } while (ret);
    assert_int_equal(errinfo, GTA_ERROR_ENUM_NO_MORE_ITEMS);
    assert_int_equal(h_enum, GTA_HANDLE_INVALID);
    assert_int_equal(1, basic_access_token_descriptor_cnt);
    assert_int_equal(1, pers_derived_access_token_descriptor_cnt);

    assert_false(gta_access_policy_destroy(h_access_policy, NULL));
    assert_true(gta_access_policy_destroy(h_access_policy, &errinfo));
}

static void
test_gta_secmem(void ** state)
{
    /* @todo Add negative tests, e.g., freeing invalid pointers, double free,
             read after free ... */
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    void * p_0, * p_1, * p_2, * p_3, * p_4, * p_5;

    assert_null(gta_secmem_calloc(NULL, 0, sizeof(uint8_t), NULL));
    p_0 = gta_secmem_calloc(NULL, 0, sizeof(uint8_t), &errinfo);
    assert_null(p_0);
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    p_0 = gta_secmem_calloc(framework_test_params->h_ctx, 0, sizeof(uint8_t), &errinfo);
    assert_non_null(p_0);

    p_1 = gta_secmem_calloc(framework_test_params->h_ctx, 0, sizeof(uint8_t), &errinfo);
    assert_non_null(p_1);

    p_2 = gta_secmem_calloc(framework_test_params->h_ctx, 0, sizeof(uint8_t), &errinfo);
    assert_non_null(p_2);

    p_3 = gta_secmem_calloc(framework_test_params->h_ctx, 0, sizeof(uint8_t), &errinfo);
    assert_non_null(p_3);

    p_4 = gta_secmem_calloc(framework_test_params->h_ctx, 0, sizeof(uint8_t), &errinfo);
    assert_non_null(p_4);

    p_5 = gta_secmem_checkptr(NULL, p_4, &errinfo);
    assert_null(p_5);
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    errinfo = 0;
    p_5 = gta_secmem_checkptr(framework_test_params->h_ctx, NULL, &errinfo);
    assert_null(p_5);
    //assert_int_equal(errinfo, 0);

    p_5 = gta_secmem_checkptr(framework_test_params->h_ctx, p_4, &errinfo);
    //assert_int_equal(p_4, p_5); TODO!

    assert_false(gta_secmem_free(NULL, p_2, NULL));
    assert_false(gta_secmem_free(NULL, p_2, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_secmem_free(framework_test_params->h_ctx, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_PTR_INVALID);

    /* free middle block */
    assert_true(gta_secmem_free(framework_test_params->h_ctx, p_2, &errinfo));

    /* free first block */
    assert_true(gta_secmem_free(framework_test_params->h_ctx, p_0, &errinfo));

    /* free last block */
    assert_true(gta_secmem_free(framework_test_params->h_ctx, p_4, &errinfo));

    /* free remaining blocks */
    assert_true(gta_secmem_free(framework_test_params->h_ctx, p_1, &errinfo));
    assert_true(gta_secmem_free(framework_test_params->h_ctx, p_3, &errinfo));
}

static void
test_gta_mutex(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_mutex_t mutex = GTA_HANDLE_INVALID;

    /* no mutex */
    /* mutex create */
    mutex = gta_mutex_create(NULL);
    assert_null(mutex);

    mutex = gta_mutex_create(framework_test_params->h_ctx);
    assert_non_null(mutex);

    /* mutex lock */
    assert_false(gta_mutex_lock(NULL, NULL));
    assert_false(gta_mutex_lock(framework_test_params->h_ctx, NULL));
    assert_true(gta_mutex_lock(framework_test_params->h_ctx, mutex));

    /* mutex unlock */
    assert_false(gta_mutex_unlock(NULL, NULL));
    assert_false(gta_mutex_unlock(framework_test_params->h_ctx, NULL));
    assert_true(gta_mutex_unlock(framework_test_params->h_ctx, mutex));

    /* mutex destroy */
    assert_false(gta_mutex_destroy(NULL, NULL));
    assert_false(gta_mutex_destroy(framework_test_params->h_ctx, NULL));
    assert_true(gta_mutex_destroy(framework_test_params->h_ctx, mutex));

    /* platform specific mutex */
    /* mutex create */
    mutex = GTA_HANDLE_INVALID;
    mutex = gta_mutex_create(framework_test_params->h_ctx_mutex);
    assert_non_null(mutex);

    /* mutex lock */
    assert_false(gta_mutex_lock(framework_test_params->h_ctx_mutex, NULL));
    assert_true(gta_mutex_lock(framework_test_params->h_ctx_mutex, mutex));

    /* mutex unlock */
    assert_false(gta_mutex_unlock(framework_test_params->h_ctx_mutex, NULL));
    assert_true(gta_mutex_unlock(framework_test_params->h_ctx_mutex, mutex));

    /* mutex destroy */
    assert_false(gta_mutex_destroy(framework_test_params->h_ctx_mutex, NULL));
    assert_true(gta_mutex_destroy(framework_test_params->h_ctx_mutex, mutex));
}

static void
test_gta_identifier(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gtaio_ostream_t identifier_type = { 0 };
    gtaio_ostream_t identifier_value = { 0 };

    assert_false(gta_identifier_assign(framework_test_params->h_inst,
        NULL, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    /* should fail, because an identifier with this name already exists */
    assert_false(gta_identifier_assign(framework_test_params->h_inst,
        "identifier_type", "identifier2", &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_NAME_ALREADY_EXISTS);

    assert_true(gta_identifier_assign(framework_test_params->h_inst,
        "identifier_type", "identifier4", &errinfo));

    /* negative tests for gta_identifier_enumerate */
    assert_false(gta_identifier_enumerate(NULL, NULL, NULL, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_identifier_enumerate(NULL, &h_enum, &identifier_type,
        &identifier_value, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
}

static void
test_gta_personality(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    struct gta_protection_properties_t protection_properties = { 0 };
    gtaio_istream_t personality_content = { 0 };
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gtaio_ostream_t personality_name = { 0 };

    /* gta_personality_create */
    assert_false(gta_personality_create(framework_test_params->h_inst, NULL,
        NULL, NULL, NULL, NULL, NULL, protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    /* should fail, because a personality with this name already exists */
    assert_false(gta_personality_create(framework_test_params->h_inst,
        "identifier", "personality2", "provider_test", "profile1", NULL, NULL,
        protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_NAME_ALREADY_EXISTS);

    assert_true(gta_personality_create(framework_test_params->h_inst,
        "identifier","personality4", "provider_test", "profile1", NULL, NULL,
        protection_properties, &errinfo));

    /* gta_personality_deploy */
    assert_false(gta_personality_deploy(framework_test_params->h_inst, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    /* should fail, because a personality with this name already exists */
    assert_false(gta_personality_deploy(framework_test_params->h_inst,
        "identifier", "personality2", "provider_test", "profile1",
        (gtaio_istream_t *)&personality_content, NULL, NULL,
        protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_NAME_ALREADY_EXISTS);

    assert_true(gta_personality_deploy(framework_test_params->h_inst,
        "identifier", "personality4", "provider_test", "profile1",
        (gtaio_istream_t *)&personality_content, NULL, NULL,
        protection_properties, &errinfo));

    /* negative tests for gta_personality_enumerate */
    assert_false(gta_personality_enumerate(NULL, "identifier1", &h_enum, 99,
        &personality_name, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_personality_enumerate(framework_test_params->h_inst,
        NULL, &h_enum, 99, &personality_name, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate(framework_test_params->h_inst,
        "identifier1", &h_enum, 99, &personality_name, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate(framework_test_params->h_inst,
        "identifier1", &h_enum, 99, NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
}

static void
test_gta_context_get_provider_params(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_null(gta_context_get_provider_params(NULL, NULL));
    assert_null(gta_context_get_provider_params(NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    assert_non_null(gta_context_get_provider_params(framework_test_params->h_ctx,
        &errinfo));
}

static void
test_gta_context_get_params(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_null(gta_context_get_params(NULL, NULL));
    assert_null(gta_context_get_params(NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    assert_non_null(gta_context_get_params(framework_test_params->h_ctx,
        &errinfo));
}

static void
test_gta_provider_get_params(void ** state)
{
    // struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_null(gta_provider_get_params(NULL, NULL));

    assert_null(gta_provider_get_params(NULL, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    /*
     * This function can only be called from a provider, because of the wrapped
     * instance handle. We only do negative tests here. 
     *
    assert_non_null(gta_provider_get_params(framework_test_params->h_inst,
        &errinfo));
    */
}

static void
test_gta_access_token_get_physical_presence(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t physical_presence_token = { 0 };

    assert_false(gta_access_token_get_physical_presence(NULL,
        physical_presence_token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_access_token_get_physical_presence(framework_test_params->h_inst,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_access_token_get_physical_presence(framework_test_params->h_inst,
        physical_presence_token,
        &errinfo));
}

static void
test_gta_access_token_get_issuing(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t granting_token = { 0 };

    assert_false(gta_access_token_get_issuing(NULL,
        granting_token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_access_token_get_issuing(framework_test_params->h_inst,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_access_token_get_issuing(framework_test_params->h_inst,
        granting_token,
        &errinfo));
}

static void
test_gta_access_token_get_basic(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t granting_token = { 0 };
    gta_access_token_t token = { 0 };

    assert_false(gta_access_token_get_basic(NULL,
        granting_token,
        "personality_name",
        GTA_ACCESS_TOKEN_USAGE_USE,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_access_token_get_basic(framework_test_params->h_inst,
        NULL,
        "personality_name",
        GTA_ACCESS_TOKEN_USAGE_USE,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_access_token_get_basic(framework_test_params->h_inst,
        granting_token,
        NULL,
        GTA_ACCESS_TOKEN_USAGE_USE,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_access_token_get_basic(framework_test_params->h_inst,
        granting_token,
        "personality_name",
        3,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_access_token_get_basic(framework_test_params->h_inst,
        granting_token,
        "personality_name",
        GTA_ACCESS_TOKEN_USAGE_USE,
        token,
        &errinfo));
}

static void
test_gta_access_token_get_pers_derived(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t token = { 0 };

    assert_false(gta_access_token_get_pers_derived(NULL,
        "personality_name",
        GTA_ACCESS_TOKEN_USAGE_USE,
        &token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_access_token_get_pers_derived(framework_test_params->h_ctx,
        NULL,
        GTA_ACCESS_TOKEN_USAGE_USE,
        &token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_access_token_get_pers_derived(framework_test_params->h_ctx,
        "personality_name",
        3,
        &token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_access_token_get_pers_derived(framework_test_params->h_ctx,
        "personality_name",
        GTA_ACCESS_TOKEN_USAGE_USE,
        &token,
        &errinfo));
}

static void
test_gta_access_token_revoke(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t token = { 0 };

    assert_false(gta_access_token_revoke(NULL,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_access_token_revoke(framework_test_params->h_inst,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_access_token_revoke(framework_test_params->h_inst,
        token,
        &errinfo));
}

static void
test_gta_context_auth_set_access_token(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_access_token_t token = { 0 };

    assert_false(gta_context_auth_set_access_token(NULL,
        token,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_context_auth_set_access_token(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_context_auth_set_access_token(framework_test_params->h_ctx,
        token,
        &errinfo));
}

static void
test_gta_context_auth_get_challenge(void ** state)
{
    /* todo */
}

static void
test_gta_context_auth_set_random(void ** state)
{
    /* todo */
}

static void
test_gta_context_get_attribute(void ** state)
{
    /* todo */
}

static void
test_gta_context_set_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t attrvalue = { 0 };

    assert_false(gta_context_set_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL));

    assert_false(gta_context_set_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_context_set_attribute(framework_test_params->h_ctx,
        "attrtype",
        &attrvalue,
        NULL));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_context_set_attribute(NULL,
        "attrtype",
        &attrvalue,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_context_set_attribute(framework_test_params->h_ctx,
        "attrtype",
        &attrvalue,
        &errinfo));
}

static void
test_gta_devicestate_transition(void ** state)
{
    /* todo */
}

static void
test_gta_devicestate_recede(void ** state)
{
    /* todo */
}

static void
test_gta_devicestate_attestate(void ** state)
{
    /* todo */
}

static void
test_gta_personality_enumerate_application(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t personality_name = { 0 };
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        NULL,
        NULL,
        99,
        NULL,
        NULL));

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        NULL,
        NULL,
        99,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate_application(NULL,
        "application",
        &h_enum,
        99,
        &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        NULL,
        &h_enum,
        99,
        &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        "application",
        NULL,
        99,
        &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        "application",
        &h_enum,
        99,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        "application",
        &h_enum,
        99,
        &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);
}

static void
test_gta_personality_enroll(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t enrollment_info = { 0 };

    assert_false(gta_personality_enroll(framework_test_params->h_ctx,
        NULL,
        NULL));

    assert_false(gta_personality_enroll(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_enroll(NULL,
        &enrollment_info,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_enroll(framework_test_params->h_ctx,
        &enrollment_info,
        &errinfo));
}

static void
test_gta_personality_enroll_auth(void ** state)
{
    /* todo */
}

static void
test_gta_personality_attestate(void ** state)
{
    /* todo */
}

static void
test_gta_personality_remove(void ** state)
{
    /* todo */
}

static void
test_gta_personality_deactivate(void ** state)
{
    /* todo */
}

static void
test_gta_personality_activate(void ** state)
{
    /* todo */
}

static void
test_gta_personality_add_trusted_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t attrvalue = { 0 };

    assert_false(gta_personality_add_trusted_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL,
        NULL));

    assert_false(gta_personality_add_trusted_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_add_trusted_attribute(NULL,
        "attrtype",
        "attrname",
        &attrvalue,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_add_trusted_attribute(framework_test_params->h_ctx,
        "attrtype",
        "attrname",
        &attrvalue,
        &errinfo));
}

static void
test_gta_personality_add_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t attrvalue = { 0 };

    assert_false(gta_personality_add_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL,
        NULL));

    assert_false(gta_personality_add_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_add_attribute(NULL,
        "attrtype",
        "attrname",
        &attrvalue,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_add_attribute(framework_test_params->h_ctx,
        "attrtype",
        "attrname",
        &attrvalue,
        &errinfo));
}

static void
test_gta_personality_get_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_ostream_t attrvalue = { 0 };

    assert_false(gta_personality_get_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL));

    assert_false(gta_personality_get_attribute(framework_test_params->h_ctx,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_get_attribute(NULL,
        "attrname",
        &attrvalue,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_get_attribute(framework_test_params->h_ctx,
        "attrname",
        &attrvalue,
        &errinfo));
}

static void
test_gta_personality_remove_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_false(gta_personality_remove_attribute(framework_test_params->h_ctx,
        NULL,
        NULL));

    assert_false(gta_personality_remove_attribute(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_remove_attribute(NULL,
        "attrname",
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_remove_attribute(framework_test_params->h_ctx,
        "attrname",
        &errinfo));
}

static void
test_gta_personality_deactivate_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_false(gta_personality_deactivate_attribute(framework_test_params->h_ctx,
        NULL,
        NULL));

    assert_false(gta_personality_deactivate_attribute(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_deactivate_attribute(NULL,
        "attrname",
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_deactivate_attribute(framework_test_params->h_ctx,
        "attrname",
        &errinfo));
}

static void
test_gta_personality_activate_attribute(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_false(gta_personality_activate_attribute(framework_test_params->h_ctx,
        NULL,
        NULL));

    assert_false(gta_personality_activate_attribute(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_personality_activate_attribute(NULL,
        "attrname",
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_personality_activate_attribute(framework_test_params->h_ctx,
        "attrname",
        &errinfo));
}

static void
test_gta_seal_data(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t data = { 0 };
    gtaio_ostream_t protected_data = { 0 };

    assert_false(gta_seal_data(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL));

    assert_false(gta_seal_data(framework_test_params->h_ctx,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_seal_data(NULL,
        &data,
        &protected_data,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_seal_data(framework_test_params->h_ctx,
        &data,
        &protected_data,
        &errinfo));
}

static void
test_gta_unseal_data(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t protected_data = { 0 };
    gtaio_ostream_t data = { 0 };

    assert_false(gta_unseal_data(framework_test_params->h_ctx,
        NULL,
        NULL,
        NULL));

    assert_false(gta_unseal_data(framework_test_params->h_ctx,
        NULL,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_unseal_data(NULL,
        &protected_data,
        &data,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_unseal_data(framework_test_params->h_ctx,
        &protected_data,
        &data,
        &errinfo));
}

static void
test_gta_verify(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t claim = { 0 };

    assert_false(gta_verify(framework_test_params->h_ctx,
        NULL,
        NULL));

    assert_false(gta_verify(framework_test_params->h_ctx,
        NULL,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_false(gta_verify(NULL,
        &claim,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);

    assert_true(gta_verify(framework_test_params->h_ctx,
        &claim,
        &errinfo));
}

static void
test_gta_authenticate_data_detached(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gtaio_istream_t data = { 0 };
    gtaio_ostream_t seal = { 0 };

    assert_false(gta_authenticate_data_detached(framework_test_params->h_ctx,
        &data, &seal, NULL));
    assert_false(gta_authenticate_data_detached(NULL, &data, &seal, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_HANDLE_INVALID);
    assert_false(gta_authenticate_data_detached(framework_test_params->h_ctx,
        NULL, &seal, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INVALID_PARAMETER);

    assert_true(gta_authenticate_data_detached(framework_test_params->h_ctx,
        &data, &seal, &errinfo));
}

static void
test_gta_verify_data_detached(void ** state)
{
    /* todo */
}

static void
test_gta_security_association_initialize(void ** state)
{
    /* todo */
}

static void
test_gta_security_association_accept(void ** state)
{
    /* todo */
}

static void
test_gta_security_association_destroy(void ** state)
{
    /* todo */
}

static void
test_gta_seal_message(void ** state)
{
    /* todo */
}

static void
test_gta_unseal_message(void ** state)
{
    /* todo */
}

static void
test_gta_get_random_bytes(void ** state)
{
    /* todo */
}

static void
test_gta_trustex_function_install(void ** state)
{
    /* todo */
}

static void
test_gta_trustex_function_uninstall(void ** state)
{
    /* todo */
}

static void
test_gta_trustex_function_execute(void ** state)
{
    /* todo */
}

static void
test_gta_trustex_function_terminate(void ** state)
{
    /* todo */
}

static void
test_gta_identifier_assign_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    assert_false(gta_identifier_assign(framework_test_params->h_inst,
        "identifier_type", "identifier4", &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_identifier_enumerate_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gtaio_ostream_t identifier_type = { 0 };
    gtaio_ostream_t identifier_value = { 0 };

    assert_false(gta_identifier_enumerate(framework_test_params->h_inst,
        &h_enum, &identifier_type, &identifier_value, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_personality_create_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    struct gta_protection_properties_t protection_properties = { 0 };

    assert_false(gta_personality_create(framework_test_params->h_inst,
        "identifier4", "personality4", "application", "profile1", NULL, NULL,
        protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_personality_deploy_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    struct gta_protection_properties_t protection_properties = { 0 };
    gtaio_istream_t personality_content = { 0 };

    assert_false(gta_personality_deploy(framework_test_params->h_inst,
        "identifier4", "personality4", "application", "profile1",
        (gtaio_istream_t *)&personality_content, NULL, NULL,
        protection_properties, &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_personality_enumerate_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gtaio_ostream_t personality_name = { 0 };

    assert_false(gta_personality_enumerate(framework_test_params->h_inst,
        "identifier4", &h_enum, GTA_PERSONALITY_ENUM_ALL, &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_personality_enumerate_application_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;
    gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
    gtaio_ostream_t personality_name = { 0 };

    assert_false(gta_personality_enumerate_application(framework_test_params->h_inst,
        "application", &h_enum, GTA_PERSONALITY_ENUM_ALL, &personality_name,
        &errinfo));
    assert_int_equal(errinfo, GTA_ERROR_INTERNAL_ERROR);
}

static void
test_gta_context_open_wo_provider(void ** state)
{
    struct framework_test_params_t * framework_test_params = (struct framework_test_params_t *)(*state);
    gta_errinfo_t errinfo = 0;

    framework_test_params->h_ctx = gta_context_open(framework_test_params->h_inst,
        "personality2",
        "profile1",
        &errinfo);
    assert_null(framework_test_params->h_ctx);
}

int ts_framework(void)
{
    const struct CMUnitTest tests_framework[] = {
        cmocka_unit_test(test_gta_secmem),
        cmocka_unit_test(test_gta_mutex),
        cmocka_unit_test(test_gta_identifier),
        cmocka_unit_test(test_gta_personality),
        cmocka_unit_test(test_gta_context_get_provider_params),
        cmocka_unit_test(test_gta_context_get_params),
        cmocka_unit_test(test_gta_provider_get_params),
        cmocka_unit_test(test_gta_access_policy),
        cmocka_unit_test(test_gta_access_token_get_physical_presence),
        cmocka_unit_test(test_gta_access_token_get_issuing),
        cmocka_unit_test(test_gta_access_token_get_basic),
        cmocka_unit_test(test_gta_access_token_get_pers_derived),
        cmocka_unit_test(test_gta_access_token_revoke),
        /* TODO */
        cmocka_unit_test(test_gta_context_auth_set_access_token),
        cmocka_unit_test(test_gta_context_auth_get_challenge),
        cmocka_unit_test(test_gta_context_auth_set_random),
        cmocka_unit_test(test_gta_context_get_attribute),
        cmocka_unit_test(test_gta_context_set_attribute),
        cmocka_unit_test(test_gta_devicestate_transition),
        cmocka_unit_test(test_gta_devicestate_recede),
        cmocka_unit_test(test_gta_devicestate_attestate),
        cmocka_unit_test(test_gta_personality_enumerate_application),
        cmocka_unit_test(test_gta_personality_enroll),
        cmocka_unit_test(test_gta_personality_enroll_auth),
        cmocka_unit_test(test_gta_personality_attestate),
        cmocka_unit_test(test_gta_personality_remove),
        cmocka_unit_test(test_gta_personality_deactivate),
        cmocka_unit_test(test_gta_personality_activate),
        cmocka_unit_test(test_gta_personality_add_trusted_attribute),
        cmocka_unit_test(test_gta_personality_add_attribute),
        cmocka_unit_test(test_gta_personality_get_attribute),
        cmocka_unit_test(test_gta_personality_remove_attribute),
        cmocka_unit_test(test_gta_personality_deactivate_attribute),
        cmocka_unit_test(test_gta_personality_activate_attribute),
        cmocka_unit_test(test_gta_seal_data),
        cmocka_unit_test(test_gta_unseal_data),
        cmocka_unit_test(test_gta_verify),
        cmocka_unit_test(test_gta_authenticate_data_detached),
        cmocka_unit_test(test_gta_verify_data_detached),
        cmocka_unit_test(test_gta_security_association_initialize),
        cmocka_unit_test(test_gta_security_association_accept),
        cmocka_unit_test(test_gta_security_association_destroy),
        cmocka_unit_test(test_gta_seal_message),
        cmocka_unit_test(test_gta_unseal_message),
        cmocka_unit_test(test_gta_get_random_bytes),
        cmocka_unit_test(test_gta_trustex_function_install),
        cmocka_unit_test(test_gta_trustex_function_uninstall),
        cmocka_unit_test(test_gta_trustex_function_execute),
        cmocka_unit_test(test_gta_trustex_function_terminate),
    };

    return cmocka_run_group_tests( tests_framework,
                   init_suite_framework,
                   clean_suite_framework);
}

int framework_exceptions(void)
{
    const struct CMUnitTest tests_framework_exceptions[] = {
        cmocka_unit_test(test_gta_identifier_assign_wo_provider),
        cmocka_unit_test(test_gta_identifier_enumerate_wo_provider),
        cmocka_unit_test(test_gta_personality_create_wo_provider),
        cmocka_unit_test(test_gta_personality_deploy_wo_provider),
        cmocka_unit_test(test_gta_personality_enumerate_wo_provider),
        cmocka_unit_test(test_gta_personality_enumerate_application_wo_provider),
        cmocka_unit_test(test_gta_context_open_wo_provider),
    };

    return cmocka_run_group_tests( tests_framework_exceptions,
                   init_suite_framework_exceptions,
                   clean_suite_framework);
}

int main(void)
{
    int result = 0;
    result |= ts_framework();
    result |= framework_exceptions();
    return result;
}

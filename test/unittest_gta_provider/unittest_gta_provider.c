/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024-2025, Siemens AG
 **********************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <gta_api.h>

static const struct gta_function_list_t g_my_function_list;

/* provider instance global data */
struct unittest_provider_params_t {
    void * p_some_provider_param;
};


/* provider local context specific data */
struct unittest_provider_context_params_t {
    void * p_some_context_param;
};

void
unittest_provider_free_params(void * p_params)
{
    /* p_params have been allocated using gta_secmem_calloc() an
       are released automatically.
       Since there are no additional resources there's nothing
       to do at the moment. */
}

GTA_DECLARE_FUNCTION(const struct gta_function_list_t *, unittest_provider_init, ());
GTA_DEFINE_FUNCTION(const struct gta_function_list_t *, unittest_provider_init,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * provider_init_config,
    gtaio_ostream_t * logging,
    void ** pp_params,
    void (** ppf_free_params)(void * p_params),
    gta_errinfo_t * p_errinfo
))
{
    struct unittest_provider_params_t * p_provider_params = NULL;
    p_provider_params = gta_secmem_calloc(h_ctx, 1, 1, p_errinfo);
    if (p_provider_params) {
        *pp_params = p_provider_params;
    }
    *ppf_free_params = unittest_provider_free_params;

#if 1 /* internal test */
    if (gta_context_get_provider_params(h_ctx, p_errinfo) != p_provider_params)
    {
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return NULL;
    }
#endif

    return &g_my_function_list;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_access_token_get_physical_presence,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t physical_presence_token,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_access_token_get_issuing,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t granting_token,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_access_token_get_basic,
(
    gta_instance_handle_t h_inst,
    const gta_access_token_t granting_token,
    const gta_personality_name_t personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t basic_access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_access_token_get_pers_derived,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t target_personality_name,
    gta_access_token_usage_t usage,
    gta_access_token_t * p_pers_derived_access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_access_token_revoke,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token_tbr,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}

GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_context_auth_set_access_token,
(
    gta_context_handle_t h_ctx,
    const gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_context_auth_get_challenge,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * challenge,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_context_auth_set_random,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * random,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_context_get_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_context_set_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_context_attribute_type_t attrtype,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_provider_context_open,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t personality,
    const gta_profile_name_t profile,
    void ** pp_params,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = true;

    struct unittest_provider_context_params_t * p_context_params = NULL;

    p_context_params = gta_secmem_calloc(h_ctx, 1, sizeof(struct unittest_provider_context_params_t), p_errinfo);
    if (p_context_params) {
        *pp_params = p_context_params;
    }

#if 1 /* internal test */
    if (gta_context_get_params(h_ctx, p_errinfo) != p_context_params)
    {
        /* p_context_params is not cleaned up */
        *p_errinfo = GTA_ERROR_INTERNAL_ERROR;
        return false;
    }
#endif

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_provider_context_close,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_devicestate_transition,
(
    gta_instance_handle_t h_inst,
    gta_access_policy_handle_t h_auth_recede,
    size_t owner_lock_count,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_devicestate_recede,
(
    gta_instance_handle_t h_inst,
    gta_access_token_t access_token,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_devicestate_attestate,
(
    gta_context_handle_t h_context,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * attestation,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_identifier_assign,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_type_t identifier_type,
    const gta_identifier_value_t identifier_value,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_identifier_enumerate,
(
    gta_instance_handle_t h_inst,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * identifier_type,
    gtaio_ostream_t * identifier_value,
    gta_errinfo_t * p_errinfo
    ))
{
    bool b_ret = false;

    /* check parameters */
    if ((NULL != ph_enum)
        || (NULL == identifier_type)
        || (NULL == identifier_value)) {

        /* hardcoded behaviour for framework tests */
        #define GTA_HANDLE_ENUM_1 ((gta_context_handle_t)-2)
        #define GTA_HANDLE_ENUM_2 ((gta_context_handle_t)-3)
        #define GTA_HANDLE_ENUM_3 ((gta_context_handle_t)-4)
        
        if (GTA_HANDLE_INVALID == *ph_enum){
            *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        } else if (GTA_HANDLE_ENUM_FIRST == *ph_enum) {
            identifier_type->write(identifier_type, "type1",
                6, p_errinfo);
            identifier_value->write(identifier_value, "identifier1",
                12, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_1;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_1 == *ph_enum) {
            identifier_type->write(identifier_type, "type2",
                6, p_errinfo);
            identifier_value->write(identifier_value, "identifier2",
                12, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_2;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_2 == *ph_enum) {
            identifier_type->write(identifier_type, "type3",
                6, p_errinfo);
            identifier_value->write(identifier_value, "identifier3",
                12, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_3;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_3 == *ph_enum) {
            *ph_enum = GTA_HANDLE_INVALID;
            *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
        }
    } else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_enumerate,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool b_ret = false;

    /* check parameters */
    if ((NULL != ph_enum)
        || (NULL == personality_name)) {

        /* hardcoded behaviour for framework tests */
        #define GTA_HANDLE_ENUM_1 ((gta_context_handle_t)-2)
        #define GTA_HANDLE_ENUM_2 ((gta_context_handle_t)-3)
        #define GTA_HANDLE_ENUM_3 ((gta_context_handle_t)-4)
        
        if (GTA_HANDLE_INVALID == *ph_enum){
            *p_errinfo = GTA_ERROR_HANDLE_INVALID;
        } else if (GTA_HANDLE_ENUM_FIRST == *ph_enum) {
            personality_name->write(personality_name, "personality1",
                13, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_1;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_1 == *ph_enum) {
            personality_name->write(personality_name, "personality2",
                13, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_2;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_2 == *ph_enum) {
            personality_name->write(personality_name, "personality3",
                13, p_errinfo);
            *ph_enum = GTA_HANDLE_ENUM_3;
            b_ret = true;
        } else if (GTA_HANDLE_ENUM_3 == *ph_enum) {
            *ph_enum = GTA_HANDLE_INVALID;
            *p_errinfo = GTA_ERROR_ENUM_NO_MORE_ITEMS;
        }
    } else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return b_ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_enumerate_application,
(
    gta_instance_handle_t h_inst,
    const gta_application_name_t application_name,
    gta_enum_handle_t * ph_enum,
    gta_personality_enum_flags_t flags,
    gtaio_ostream_t * personality_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_deploy,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gtaio_istream_t * personality_content,
    gta_access_policy_handle_t h_auth_use,
    gta_access_policy_handle_t h_auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_create,
(
    gta_instance_handle_t h_inst,
    const gta_identifier_value_t identifier_value,
    const gta_personality_name_t personality_name,
    const gta_application_name_t application,
    const gta_profile_name_t profile,
    gta_access_policy_handle_t h_auth_use,
    gta_access_policy_handle_t h_auth_admin,
    struct gta_protection_properties_t requested_protection_properties,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_enroll,
(
    gta_context_handle_t h_ctx,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_enroll_auth,
(
    gta_context_handle_t h_ctx,
    gta_context_handle_t h_auth_ctx,
    gtaio_ostream_t * p_personality_enrollment_info,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_attestate,
(
    gta_context_handle_t h_ctx,
    const gta_personality_name_t personality_name,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * p_attestation_data,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_remove,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_deactivate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_activate,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_add_trusted_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_add_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_type_t attrtype,
    const gta_personality_attribute_name_t attrname,
    gtaio_istream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_get_attribute, (
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gtaio_ostream_t * p_attrvalue,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_remove_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_deactivate_attribute,
(
    gta_context_handle_t h_ctx,
    const gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_activate_attribute,
(
    gta_context_handle_t h_ctx,
    gta_personality_attribute_name_t attrname,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_personality_attributes_enumerate,
(
    gta_instance_handle_t h_inst,
    const gta_personality_name_t personality_name,
    gta_enum_handle_t * ph_enum,
    gtaio_ostream_t * attribute_type,
    gtaio_ostream_t * attribute_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_seal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * protected_data,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_unseal_data,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * protected_data,
    gtaio_ostream_t * data,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_verify,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * claim,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_authenticate_data_detached,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_ostream_t * seal,
    gta_errinfo_t * p_errinfo
    ))
{
    return true;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_verify_data_detached,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * data,
    gtaio_istream_t * seal,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_security_association_initialize,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * in,
    gtaio_ostream_t * out,
    bool * pb_finished,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_security_association_accept,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * in,
    gtaio_ostream_t * out,
    bool * pb_finished,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_security_association_destroy,
(
    gta_context_handle_t h_ctx,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_seal_message,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * msg,
    gtaio_ostream_t * sealed_msg,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_unseal_message,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * sealed_msg,
    gtaio_ostream_t * msg,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_get_random_bytes,
(
    size_t num_bytes,
    gtaio_ostream_t * rnd_stream,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_attestate,
(
    gta_context_handle_t h_ctx,
    gtaio_istream_t * nonce,
    gtaio_ostream_t * attestation_data,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_trustex_function_install,
(
    const char * function_name,
    gta_profile_name_t profile_name,
    gtaio_istream_t function,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_trustex_function_uninstall,
(
    const char * function_name,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_trustex_function_execute,
(
    const char * function_name,
    gta_handle_t function_handle,
    gtaio_istream_t input,
    gtaio_ostream_t output,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


GTA_DEFINE_FUNCTION(bool, unittest_provider_gta_trustex_function_terminate,
(
    gta_handle_t function_handle,
    gta_errinfo_t * p_errinfo
    ))
{
    bool ret = false;

    *p_errinfo = GTA_ERROR_INTERNAL_ERROR;

    /* ... */

    return ret;
}


static const struct gta_function_list_t g_my_function_list =
{
    unittest_provider_gta_access_token_get_physical_presence,
    unittest_provider_gta_access_token_get_issuing,
    unittest_provider_gta_access_token_get_basic,
    unittest_provider_gta_access_token_get_pers_derived,
    unittest_provider_gta_access_token_revoke,
    unittest_provider_gta_provider_context_open,
    unittest_provider_gta_provider_context_close,
    unittest_provider_gta_context_auth_set_access_token,
    unittest_provider_gta_context_auth_get_challenge,
    unittest_provider_gta_context_auth_set_random,
    unittest_provider_gta_context_get_attribute,
    unittest_provider_gta_context_set_attribute,
    unittest_provider_gta_devicestate_transition,
    unittest_provider_gta_devicestate_recede,
    unittest_provider_gta_devicestate_attestate,
    unittest_provider_gta_identifier_assign,
    unittest_provider_gta_identifier_enumerate,
    unittest_provider_gta_personality_enumerate,
    unittest_provider_gta_personality_enumerate_application,
    unittest_provider_gta_personality_deploy,
    unittest_provider_gta_personality_create,
    unittest_provider_gta_personality_enroll,
    unittest_provider_gta_personality_enroll_auth,
    unittest_provider_gta_personality_attestate,
    unittest_provider_gta_personality_remove,
    unittest_provider_gta_personality_deactivate,
    unittest_provider_gta_personality_activate,
    unittest_provider_gta_personality_add_trusted_attribute,
    unittest_provider_gta_personality_add_attribute,
    unittest_provider_gta_personality_get_attribute,
    unittest_provider_gta_personality_remove_attribute,
    unittest_provider_gta_personality_deactivate_attribute,
    unittest_provider_gta_personality_activate_attribute,
    unittest_provider_gta_personality_attributes_enumerate,
    unittest_provider_gta_seal_data,
    unittest_provider_gta_unseal_data,
    unittest_provider_gta_verify,
    unittest_provider_gta_authenticate_data_detached,
    unittest_provider_gta_verify_data_detached,
    unittest_provider_gta_security_association_initialize,
    unittest_provider_gta_security_association_accept,
    unittest_provider_gta_security_association_destroy,
    unittest_provider_gta_seal_message,
    unittest_provider_gta_unseal_message,
    unittest_provider_gta_get_random_bytes,
    unittest_provider_gta_attestate,
    unittest_provider_gta_trustex_function_install,
    unittest_provider_gta_trustex_function_uninstall,
    unittest_provider_gta_trustex_function_execute,
    unittest_provider_gta_trustex_function_terminate
};
